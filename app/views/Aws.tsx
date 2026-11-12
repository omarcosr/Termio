import { Column, openExternal, Row, clipboard } from "@tarve/core";
import { refresh } from "../state/store";
import { Action, Hint } from "../ui/kit";

/** Where an IAM user is created; AWS has no page that takes a ready-made key request, as Cloudflare does. */
const IAM_NEW_USER = "https://console.aws.amazon.com/iam/home#/users/create";

/** Least privilege for sync: list the bucket, read and write its objects, nothing else. */
export function s3Policy(bucket: string): string {
  const name = bucket.trim() || "YOUR-BUCKET";
  return JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      { Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${name}` },
      { Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject"], Resource: `arn:aws:s3:::${name}/*` },
    ],
  }, null, 2);
}

let copiedAt = 0;

function copyPolicy(bucket: string): void {
  clipboard.writeText(s3Policy(bucket)).then(() => {
    copiedAt = Date.now();
    refresh();
    setTimeout(refresh, 2000);
  }, () => { /* no clipboard: the steps still say what to allow */ });
}

/** The AWS side of an S3 bucket: open IAM, copy the policy for this bucket, and the steps between. */
export function AwsSetup({ bucket }: { bucket: string }) {
  const copied = Date.now() - copiedAt < 2000;
  return (
    <Column gap={8}>
      <Row gap={8}>
        <Action icon="cloud" label="Open IAM on AWS" onClick={() => openExternal(IAM_NEW_USER)} />
        <Action icon={copied ? "check" : "copy"} label={copied ? "Policy copied" : "Copy policy"} onClick={() => copyPolicy(bucket)} />
      </Row>
      <Hint>{`Create the bucket in S3 first. In IAM, create a user, add the copied policy as an inline policy (JSON tab)${bucket.trim() ? `, scoped to ${bucket.trim()}` : ": type the bucket above first, so it names it"}. Then under Security credentials create an access key (Other) and paste it here.`}</Hint>
    </Column>
  );
}
