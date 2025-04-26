
rule Trojan_Win32_SpyBot_DSK_MTB{
	meta:
		description = "Trojan:Win32/SpyBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 03 45 fc 8b 4d ?? 8a 00 32 04 11 8b 4d e4 03 4d fc 88 01 eb } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}