
rule Trojan_Win64_Strab_ARA_MTB{
	meta:
		description = "Trojan:Win64/Strab.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 30 89 04 24 8b 44 24 30 ff c8 89 44 24 30 83 3c 24 00 74 2b 48 8b 44 24 20 48 8b 4c 24 28 0f b6 09 88 08 48 8b 44 24 20 48 ff c0 48 89 44 24 20 48 8b 44 24 28 48 ff c0 48 89 44 24 28 eb be } //02 00 
		$a_01_1 = {5c 64 64 76 73 6d 5c 30 38 30 34 5f 31 36 31 34 32 36 5c 63 6d 64 5c 73 5c 6f 75 74 5c 62 69 6e 61 72 69 65 73 5c 61 6d 64 36 34 72 65 74 5c 62 69 6e 5c 61 6d 64 36 34 5c 42 6c 65 6e 64 2e 70 64 62 } //01 00  \ddvsm\0804_161426\cmd\s\out\binaries\amd64ret\bin\amd64\Blend.pdb
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4e 61 6d 65 57 } //00 00  GetClipboardFormatNameW
	condition:
		any of ($a_*)
 
}