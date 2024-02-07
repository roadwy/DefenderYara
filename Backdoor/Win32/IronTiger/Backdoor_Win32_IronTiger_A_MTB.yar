
rule Backdoor_Win32_IronTiger_A_MTB{
	meta:
		description = "Backdoor:Win32/IronTiger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 61 64 6d 69 6e } //01 00  fuckadmin
		$a_01_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 64 6f 6f 72 20 62 79 20 6f 75 72 73 65 6c 76 65 73 21 } //01 00  Welcome to door by ourselves!
		$a_01_2 = {46 77 5f 44 72 76 41 6e 74 69 } //01 00  Fw_DrvAnti
		$a_01_3 = {48 00 64 00 46 00 77 00 5f 00 41 00 6e 00 74 00 69 00 5f 00 73 00 79 00 73 00 } //01 00  HdFw_Anti_sys
		$a_01_4 = {72 75 6e 69 6e 67 } //00 00  runing
	condition:
		any of ($a_*)
 
}