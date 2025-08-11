
rule HackTool_MacOS_LinPeas_B_MTB{
	meta:
		description = "HackTool:MacOS/LinPeas.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 50 45 41 53 53 2d 6e 67 2f 73 68 32 62 69 6e 2f 73 68 32 62 69 6e 2e 67 6f } //1 /PEASS-ng/sh2bin/sh2bin.go
		$a_01_1 = {2f 6f 70 74 2f 68 6f 73 74 65 64 74 6f 6f 6c 63 61 63 68 65 2f 67 6f 2f 31 2e 31 37 2e 30 2d 72 63 31 2f 78 36 34 2f 73 72 63 2f 66 6d 74 2f 73 63 61 6e 2e 67 6f } //1 /opt/hostedtoolcache/go/1.17.0-rc1/x64/src/fmt/scan.go
		$a_01_2 = {48 8b 54 24 68 48 8b 74 24 50 48 8b 7c 24 48 48 8b 44 24 70 48 89 f9 48 8b 5c 24 30 49 39 c8 0f 8d 08 01 00 00 0f 83 2f 01 00 00 4c 89 44 24 28 49 c1 e0 04 4c 89 44 24 40 42 8b 1c 06 48 89 d0 e8 cc c9 04 00 48 89 84 24 90 00 00 00 48 8b 4c 24 40 48 8b 54 24 50 8b 5c 0a 04 48 8b 44 24 68 } //1
		$a_01_3 = {49 89 d5 48 29 f2 48 83 c2 14 48 89 54 24 58 4c 8d 7e ec 4c 89 f8 49 c1 ff 3f 4c 21 fe 4c 8d bc 34 94 00 00 00 48 39 d7 73 3f 48 89 44 24 70 4c 89 bc 24 28 01 00 00 4c 89 6c 24 68 48 8d 05 bb a3 09 00 4c 89 c3 4c 89 e9 48 89 d6 e8 2d f0 03 00 4c 8b 6c 24 68 4c 8b bc 24 28 01 00 00 49 89 c0 48 89 cf 48 8b 44 24 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}