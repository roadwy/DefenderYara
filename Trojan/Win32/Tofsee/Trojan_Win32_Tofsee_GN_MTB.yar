
rule Trojan_Win32_Tofsee_GN_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b7 59 e7 1f f7 a4 24 90 02 10 8b 84 24 90 02 10 81 84 24 90 02 10 81 6c 24 90 02 30 30 0c 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}