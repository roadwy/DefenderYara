
rule Trojan_Win32_XenoRAT_A_MTB{
	meta:
		description = "Trojan:Win32/XenoRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 83 c0 ?? 89 45 e8 83 7d e8 ?? 7d ?? 8b f4 8d 4d f7 51 6a 00 6a 00 ff ?? ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 55 ec 83 c2 ?? 89 55 ec } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}