
rule Trojan_Win32_FoggyBrass_B_dha{
	meta:
		description = "Trojan:Win32/FoggyBrass.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0e 33 c0 8a 0c 0a 0f 1f 40 00 3a 88 ?? ?? ?? 00 74 ?? 40 83 f8 ?? 72 ?? eb ?? 8b 4e ?? 83 c0 ?? 83 e0 ?? 8a } //1
		$a_01_1 = {34 73 33 43 35 4b 44 4d 6c 78 69 61 4a 31 74 4f 62 58 63 51 72 2d 65 6f 32 47 20 7a 59 41 38 39 56 66 4c 2f 71 5a 57 49 30 6b 4e 54 55 5c 67 79 46 53 64 6e 68 37 42 36 5f 6d 6a 48 77 75 50 76 } //1 4s3C5KDMlxiaJ1tObXcQr-eo2G zYA89VfL/qZWI0kNTU\gyFSdnh7B6_mjHwuPv
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}