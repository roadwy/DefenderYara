
rule Trojan_Win32_Tnega_GP_MTB{
	meta:
		description = "Trojan:Win32/Tnega.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {d8 85 40 00 5b be 90 01 04 21 c6 e8 90 01 04 50 58 31 1f 47 48 81 c6 90 01 04 39 cf 75 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}