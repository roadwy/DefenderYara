
rule Trojan_Win32_Ursnif_GXA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 0b fb 33 f7 8b 7d 08 23 7d f4 8b df 23 de 33 d9 89 9a 90 01 04 23 45 0c 33 7d f8 33 45 fc 8b 9a 90 01 04 0b fe 33 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}