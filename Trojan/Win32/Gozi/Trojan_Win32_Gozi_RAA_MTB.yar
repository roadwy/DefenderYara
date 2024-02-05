
rule Trojan_Win32_Gozi_RAA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a4 24 90 01 04 8b 84 24 90 01 04 81 84 24 90 01 04 f3 ae ac 68 81 ac 24 90 01 04 b3 30 c7 6b 81 84 24 90 01 04 21 f4 7c 36 8b 44 24 90 01 01 30 0c 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}