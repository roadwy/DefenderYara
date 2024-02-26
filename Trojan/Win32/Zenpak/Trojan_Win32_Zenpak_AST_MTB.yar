
rule Trojan_Win32_Zenpak_AST_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {67 72 65 61 74 65 72 77 68 69 63 68 50 37 76 65 72 79 67 72 61 73 73 35 64 65 65 70 00 61 49 4a 55 4d 00 65 76 65 72 79 62 72 6f 75 67 68 74 2e 56 61 69 46 6b 70 46 00 50 6e 69 67 68 74 46 4d 6f 76 69 6e 67 5a 00 64 62 6a 73 65 61 2e 68 65 53 6f 64 72 79 68 65 47 74 6f 67 65 74 68 65 72 00 68 61 76 65 66 44 6f 6e 2e 74 } //01 00 
		$a_01_1 = {53 77 64 69 76 69 64 65 64 44 69 76 69 64 65 69 41 56 6d 61 6e 79 6f 75 2e 6c 6c 79 } //01 00  SwdividedDivideiAVmanyou.lly
		$a_01_2 = {76 31 6b 69 6e 64 79 6f 75 2e 72 65 58 43 76 30 55 } //01 00  v1kindyou.reXCv0U
		$a_01_3 = {73 68 65 2e 64 69 73 6e 2e 74 79 6f 75 64 72 79 6b 69 6e 64 53 39 6e } //01 00  she.disn.tyoudrykindS9n
		$a_01_4 = {78 73 68 61 6c 6c 79 69 65 6c 64 69 6e 67 74 6f 2e 75 4e 64 72 79 61 63 61 6e 2e 74 } //01 00  xshallyieldingto.uNdryacan.t
		$a_01_5 = {68 65 72 62 77 4e 77 68 69 63 68 71 44 4d 6f 72 6e 69 6e 67 68 61 76 65 6b 69 6e 64 2e 66 69 6c 6c } //00 00  herbwNwhichqDMorninghavekind.fill
	condition:
		any of ($a_*)
 
}