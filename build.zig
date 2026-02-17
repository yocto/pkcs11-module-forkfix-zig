const std: type = @import("std");

pub fn build(b: *std.Build) void{
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "pkcs11-forkfix",
        .linkage = .dynamic,
        .root_module = mod,
    });
    lib.addIncludePath(.{ .cwd_relative="."});

    b.installArtifact(lib);
}