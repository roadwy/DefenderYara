
rule Trojan_Win32_Legendmir_NL_MTB{
	meta:
		description = "Trojan:Win32/Legendmir.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {ff 15 f8 70 40 00 85 c0 a3 90 01 04 74 15 e8 86 02 00 00 85 c0 75 0f ff 35 20 8e 40 00 90 00 } //03 00 
		$a_03_1 = {ff 15 04 71 40 00 3b c7 74 61 83 05 08 8e 40 00 10 a3 90 01 04 a1 18 8e 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}