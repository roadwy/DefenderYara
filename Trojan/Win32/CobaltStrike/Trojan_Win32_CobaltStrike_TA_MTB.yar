
rule Trojan_Win32_CobaltStrike_TA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 58 48 8b bc 24 d0 00 00 00 48 8b 74 24 30 83 e0 07 44 8a 14 07 48 8b 84 24 c0 00 00 00 44 32 14 30 48 8b 05 3b 5b 02 00 81 38 90 01 04 0f 8e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}