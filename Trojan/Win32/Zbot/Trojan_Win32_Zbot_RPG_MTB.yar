
rule Trojan_Win32_Zbot_RPG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 88 45 fc 8a 22 80 cc 01 88 d8 f6 e4 8a 3a 28 c7 8a 45 fc 88 39 08 d8 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}