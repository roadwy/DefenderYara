
rule TrojanClicker_Win32_VB_ZK_bit{
	meta:
		description = "TrojanClicker:Win32/VB.ZK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 70 00 39 00 36 00 34 00 36 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}