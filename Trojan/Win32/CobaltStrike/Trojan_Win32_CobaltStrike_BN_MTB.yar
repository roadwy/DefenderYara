
rule Trojan_Win32_CobaltStrike_BN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 33 8a 04 17 8d 4b ?? 83 e1 07 43 d2 c8 88 02 3b 5d fc 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_CobaltStrike_BN_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d2 03 d1 0f b6 ca 8b 55 ?? 0f b6 89 ?? ?? ?? ?? 32 0c 3a 88 0f 47 83 eb ?? 75 90 0a 30 00 0f b6 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}