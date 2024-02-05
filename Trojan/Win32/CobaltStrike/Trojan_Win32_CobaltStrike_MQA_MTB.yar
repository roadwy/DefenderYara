
rule Trojan_Win32_CobaltStrike_MQA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 e9 89 ca c1 e2 04 03 54 24 1c 8d 2c 0e 31 d5 89 ca c1 ea 05 03 54 24 18 31 ea 29 d3 81 c6 90 01 04 83 c0 ff 75 c1 8b 04 24 8b 54 24 10 89 1c d0 89 c3 89 4c d0 04 8b 7c 24 04 8b 44 24 0c 31 07 83 c2 01 8b 74 24 08 39 f2 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}