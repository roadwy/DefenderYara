
rule Trojan_Win32_Doina_IH_MTB{
	meta:
		description = "Trojan:Win32/Doina.IH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 84 35 90 01 04 03 c8 0f b6 c1 8b 8d 90 01 04 0f b6 84 05 90 01 04 32 44 1a 90 01 01 88 04 11 42 81 fa 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}