
rule Trojan_Win32_CobaltStrike_CO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 83 c1 90 01 01 89 4d 90 01 01 8b 55 90 01 01 3b 55 90 01 01 73 90 01 01 0f b6 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 33 d0 8b 45 90 01 01 03 45 90 01 01 88 10 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}