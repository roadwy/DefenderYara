
rule Trojan_Win32_InvisiMole_EC_MTB{
	meta:
		description = "Trojan:Win32/InvisiMole.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 08 8b f1 c1 ee 1e 33 f1 69 f6 65 89 07 6c 03 f2 89 70 04 83 c0 04 42 } //05 00 
		$a_01_1 = {f7 d8 1b c0 25 00 00 00 02 50 6a 03 6a 00 6a 01 68 00 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}