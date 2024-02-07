
rule Trojan_Win32_Injector_A_MTB{
	meta:
		description = "Trojan:Win32/Injector.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 52 65 6d 6f 76 61 6c } //01 00  StartRemoval
		$a_03_1 = {8d 49 00 8a 04 0a 34 90 01 01 88 01 83 c1 01 83 ef 01 75 f1 8d 4c 24 1c 51 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}