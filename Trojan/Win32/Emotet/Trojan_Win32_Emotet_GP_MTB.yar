
rule Trojan_Win32_Emotet_GP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c1 8b cb c1 90 02 02 33 c1 8b cb c1 90 02 02 c1 90 02 02 c1 90 02 02 81 90 02 05 c1 90 02 02 33 90 01 01 81 90 02 05 33 90 01 01 ff 90 02 07 0f 90 02 02 3b 90 02 07 5e 8b c3 90 02 03 f7 d0 c3 90 00 } //01 00 
		$a_00_1 = {f7 d8 1b c0 23 c6 5f 5e 5b c9 c3 } //00 00 
	condition:
		any of ($a_*)
 
}