
rule Trojan_Win64_Emotet_AH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {42 32 4c 16 fb 41 88 4a fc 8b cf 41 f7 e8 83 c7 03 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1c 2b c8 } //00 00 
	condition:
		any of ($a_*)
 
}