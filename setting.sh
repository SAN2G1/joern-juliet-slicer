#!/usr/bin/env bash

# 사용 전 수정이 필요한 부분
JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"

JOERN_HOME="$HOME/Documents/swvul/joern/joern-cli"
JOERN_PARSE="$JOERN_HOME/joern-parse"
JOERN="$JOERN_HOME/joern"

#######################################################

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

JAVA_VERSION="$(java -version 2>&1 | head -n 1)"

if [[ "$JAVA_VERSION" != *'"17.'* ]]; then
  echo "Java 17이 필요합니다."
  echo "현재 버전: $JAVA_VERSION"
  exit 1
fi

echo "Java 17 확인 완료: $JAVA_VERSION"
echo "java_sard_source_sink 폴더가 필요합니다."

BASE_DIR="$(pwd)"
JULIET_DIR="$BASE_DIR/juliet-java-test-suite"

git clone \
  https://github.com/UnitTestBot/juliet-java-test-suite.git \
  "$JULIET_DIR"

cd "$JULIET_DIR"

chmod +x gradlew
./gradlew :support:classes

SUPPORT_CLASSES="$JULIET_DIR/juliet-support/build/classes/java/main"
SUPPORT_JAR="$BASE_DIR/deps/juliet-support-only.jar"

mkdir -p "$BASE_DIR/deps"
rm -f "$SUPPORT_JAR"

jar --create \
  --file "$SUPPORT_JAR" \
  -C "$SUPPORT_CLASSES" \
  juliet

SERVLET_JAR="$HOME/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar"

ENV_FILE="$BASE_DIR/.env"

cat > "$ENV_FILE" <<EOF
JULIET_DIR=$JULIET_DIR
SUPPORT_JAR=$SUPPORT_JAR
SERVLET_JAR=$SERVLET_JAR
JOERN_HOME=$JOERN_HOME
JOERN_PARSE=$JOERN_PARSE
JOERN=$JOERN
EOF

cd "$BASE_DIR"

echo
echo "Juliet 저장소: $JULIET_DIR"
echo "Support JAR: $SUPPORT_JAR"
echo ".env 파일 생성 완료: $ENV_FILE"

echo
echo "Support JAR 내용:"
jar tf "$SUPPORT_JAR" | head

echo
echo ".env 내용:"
cat "$ENV_FILE"