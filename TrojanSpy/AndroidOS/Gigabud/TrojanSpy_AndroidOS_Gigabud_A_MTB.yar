
rule TrojanSpy_AndroidOS_Gigabud_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gigabud.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 61 6e 6b 43 61 72 64 49 6e 66 6f 28 62 61 6e 6b 43 61 72 64 4e 75 6d 3d } //01 00  BankCardInfo(bankCardNum=
		$a_01_1 = {63 6f 6d 2f 79 6b 2f 61 63 63 65 73 73 69 62 69 6c 69 74 79 } //01 00  com/yk/accessibility
		$a_01_2 = {67 65 74 42 61 6e 6b 43 61 72 64 4e 75 6d } //01 00  getBankCardNum
		$a_01_3 = {54 6f 75 63 68 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //01 00  TouchAccessibilityService
		$a_01_4 = {69 73 58 66 50 65 72 6d 69 73 73 69 6f 6e 4f 70 65 6e } //00 00  isXfPermissionOpen
	condition:
		any of ($a_*)
 
}