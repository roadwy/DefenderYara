
rule Trojan_Win32_Danabot_DSK_MTB{
	meta:
		description = "Trojan:Win32/Danabot.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 8b 08 81 e9 92 27 01 00 8b 55 08 89 0a 8b e5 5d } //2
		$a_02_1 = {8b 45 fc 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6d fc 01 39 5d fc 7d } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}