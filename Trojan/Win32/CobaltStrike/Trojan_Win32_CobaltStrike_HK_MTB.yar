
rule Trojan_Win32_CobaltStrike_HK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 24 83 ec 90 01 01 89 3c 24 89 0c 24 89 e1 81 c1 90 01 04 83 c1 90 01 01 33 0c 24 31 0c 24 33 0c 24 5c e9 90 00 } //01 00 
		$a_03_1 = {43 00 4b 00 94 00 4e 90 01 01 ce 32 b9 90 01 05 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}