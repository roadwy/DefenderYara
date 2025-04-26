
rule Trojan_Win32_Zbot_AU_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 03 7d ec 54 58 89 65 fc 89 7d f0 89 5d f0 33 fe 03 45 f4 89 5d ec 33 fe 01 5d ec 89 65 f4 8b 75 f4 46 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}