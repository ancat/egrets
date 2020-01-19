FROM fedora:26
RUN dnf install -y llvm clang kernel-devel make binutils git
