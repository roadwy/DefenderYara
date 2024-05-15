
rule Ransom_Win32_Play_ZA_MTB{
	meta:
		description = "Ransom:Win32/Play.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d cc d3 e0 8b 4d d0 03 4d d4 0f b6 11 0b d0 8b 45 d0 03 45 d4 88 10 e9 } //0a 00 
		$a_01_1 = {8b 45 d0 03 45 d4 0f b6 08 33 ca 8b 55 d0 03 55 d4 88 0a eb } //00 00 
	condition:
		any of ($a_*)
 
}