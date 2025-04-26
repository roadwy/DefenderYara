
rule Trojan_Win32_CobaltStrike_CPP_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 0a 88 04 1a 42 84 c0 75 } //5
		$a_03_1 = {33 db f7 d6 f7 de 81 c3 ?? ?? ?? ?? 2b f5 c1 e3 ?? f7 de f7 d0 33 d0 e2 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}