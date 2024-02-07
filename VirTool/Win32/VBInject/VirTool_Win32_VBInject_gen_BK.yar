
rule VirTool_Win32_VBInject_gen_BK{
	meta:
		description = "VirTool:Win32/VBInject.gen!BK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 00 63 00 76 00 6e 00 6a 00 6d 00 70 00 63 00 70 00 2c 00 63 00 76 00 63 00 } //01 00  Zcvnjmpcp,cvc
		$a_01_1 = {5a 00 47 00 6c 00 72 00 63 00 70 00 6c 00 63 00 72 00 } //01 00  ZGlrcplcr
		$a_01_2 = {45 00 63 00 72 00 4b 00 6d 00 62 00 73 00 6a 00 63 00 46 00 5f 00 6c 00 62 00 6a 00 63 00 55 00 } //01 00  EcrKmbsjcF_lbjcU
		$a_01_3 = {55 00 70 00 67 00 72 00 63 00 4e 00 70 00 6d 00 61 00 63 00 71 00 71 00 4b 00 63 00 6b 00 6d 00 70 00 77 00 } //01 00  UpgrcNpmacqqKckmpw
		$a_01_4 = {4c 00 72 00 53 00 6c 00 6b 00 5f 00 6e 00 54 00 67 00 63 00 75 00 4d 00 64 00 51 00 63 00 61 00 72 00 67 00 6d 00 6c 00 } //01 00  LrSlk_nTgcuMdQcargml
		$a_01_5 = {3a 00 20 00 47 00 64 00 6f 00 4b 00 74 00 57 00 20 00 3d 00 } //00 00  : GdoKtW =
	condition:
		any of ($a_*)
 
}