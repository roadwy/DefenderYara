
rule Trojan_Win32_Tofsee_GM_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a4 24 90 01 04 8b 84 24 90 01 04 81 84 24 90 02 20 81 6c 24 90 02 20 81 84 24 90 02 20 30 0c 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}