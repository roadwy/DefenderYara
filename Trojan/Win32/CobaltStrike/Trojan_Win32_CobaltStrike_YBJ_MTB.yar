
rule Trojan_Win32_CobaltStrike_YBJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c3 32 9f ?? ?? ?? ?? 8b 44 24 30 88 58 03 89 f7 c1 ef 18 8b 44 24 04 8b 5c 24 08 8b 84 03 ec 01 00 00 89 c3 c1 eb 18 32 9f ?? ?? ?? ?? 8b 7c 24 30 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}