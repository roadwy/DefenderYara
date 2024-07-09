
rule Trojan_Win32_Zbot_SIBD2_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBD2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 17 8b 4f ?? 53 b8 ?? ?? ?? ?? 55 8d 64 24 00 8b da c1 eb ?? 8b ea c1 e5 ?? 33 dd 8b e8 c1 ed ?? 83 e5 ?? 03 1c ae 8b e8 33 ea 03 dd 2b cb 8b d9 c1 eb ?? 8b e9 c1 e5 ?? 33 dd 05 ?? ?? ?? ?? 8b e8 83 e5 ?? 03 1c ae 8b e8 33 e9 03 dd 2b d3 85 c0 75 ?? 5d 89 17 89 4f } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}