
rule Trojan_Win32_Zbot_AW_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 d1 8b 55 c4 0f b6 04 0a 83 f0 5e 8b 4d bc 01 c1 89 4d bc 0f b6 4d b0 89 4d ac 8b 4d c4 83 c1 01 89 4d c4 8b 55 08 88 55 a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}