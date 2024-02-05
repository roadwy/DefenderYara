
rule Trojan_Win32_Injector_PA_MTB{
	meta:
		description = "Trojan:Win32/Injector.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 14 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d5 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 3b 81 fe 1e 10 00 00 75 90 01 01 8d 54 24 10 52 8d 44 24 18 50 6a 00 8d 4c 24 24 51 6a 00 6a 00 ff 15 90 01 04 47 3b fe 7c 90 09 08 00 81 fe 90 01 02 00 00 75 90 00 } //01 00 
		$a_02_1 = {69 c9 fd 43 03 00 56 89 0d 90 01 04 81 05 90 01 07 00 81 3d 90 01 06 00 00 8b 35 90 01 04 75 90 09 06 00 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}