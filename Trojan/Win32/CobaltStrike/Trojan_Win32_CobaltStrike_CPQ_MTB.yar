
rule Trojan_Win32_CobaltStrike_CPQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 04 0a 88 04 1a 42 84 c0 75 } //05 00 
		$a_03_1 = {c1 cf 1b 47 33 d9 c1 eb 90 01 01 03 1d 90 01 04 21 90 01 05 3b fb 78 90 01 01 c1 90 01 02 81 90 01 09 81 90 01 05 81 90 01 05 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}