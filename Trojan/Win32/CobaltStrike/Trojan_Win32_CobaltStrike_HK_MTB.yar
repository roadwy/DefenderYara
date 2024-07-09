
rule Trojan_Win32_CobaltStrike_HK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 83 ec ?? 89 3c 24 89 0c 24 89 e1 81 c1 ?? ?? ?? ?? 83 c1 ?? 33 0c 24 31 0c 24 33 0c 24 5c e9 } //1
		$a_03_1 = {43 00 4b 00 94 00 4e ?? ce 32 b9 ?? ?? ?? ?? ?? d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}