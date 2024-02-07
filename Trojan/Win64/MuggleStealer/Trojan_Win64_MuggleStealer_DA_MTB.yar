
rule Trojan_Win64_MuggleStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/MuggleStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 70 68 69 6c 2d 66 6c 79 2f 67 65 6e 65 72 61 74 65 } //01 00  github.com/phil-fly/generate
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_2 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //01 00  screenshot.png
		$a_01_3 = {43 68 72 6f 6d 65 50 77 64 } //01 00  ChromePwd
		$a_01_4 = {4c 6f 67 69 6e 20 44 61 74 61 } //01 00  Login Data
		$a_01_5 = {57 69 6e 63 72 65 64 73 } //01 00  Wincreds
		$a_01_6 = {55 70 6c 6f 61 64 46 69 6c 65 } //01 00  UploadFile
		$a_01_7 = {44 69 73 6b 49 6e 66 6f } //00 00  DiskInfo
	condition:
		any of ($a_*)
 
}