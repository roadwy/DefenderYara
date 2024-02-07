
rule Trojan_Win32_VBInject_PO_MTB{
	meta:
		description = "Trojan:Win32/VBInject.PO!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 75 00 61 00 77 00 65 00 69 00 } //01 00  Huawei
		$a_01_1 = {41 00 56 00 47 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 } //01 00  AVG Technologies
		$a_01_2 = {43 00 61 00 6d 00 53 00 74 00 75 00 64 00 69 00 6f 00 20 00 47 00 72 00 6f 00 75 00 70 00 } //01 00  CamStudio Group
		$a_01_3 = {53 00 6f 00 75 00 72 00 63 00 65 00 66 00 69 00 72 00 65 00 2c 00 20 00 49 00 6e 00 63 00 2e 00 } //01 00  Sourcefire, Inc.
		$a_01_4 = {57 00 6f 00 72 00 6c 00 64 00 63 00 6f 00 69 00 6e 00 } //01 00  Worldcoin
		$a_01_5 = {46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //00 00  FileZilla Project
	condition:
		any of ($a_*)
 
}