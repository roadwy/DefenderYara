
rule Trojan_Win32_Zbot_SIBB3_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBB3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 89 c7 be [0-10] 8a 1d [0-0a] 8a 3e 88 3f 47 46 46 50 8a 06 aa 00 5f ?? 58 e2 [0-0a] 83 ec ?? 6a ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5a 29 c2 52 6a ?? 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5a 29 c2 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}