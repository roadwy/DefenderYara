
rule Trojan_Win32_Zbot_BAK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 85 14 ff ff ff 8b 85 40 ff ff ff 8b 4d e4 8b 04 81 99 2b c2 d1 f8 89 85 3c ff ff ff 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 73 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}