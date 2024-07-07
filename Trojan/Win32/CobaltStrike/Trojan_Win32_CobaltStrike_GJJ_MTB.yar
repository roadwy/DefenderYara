
rule Trojan_Win32_CobaltStrike_GJJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 8b 45 e0 01 d0 0f b6 00 31 d8 88 01 83 45 e4 01 8b 55 e4 8b 45 d0 39 c2 0f 82 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}