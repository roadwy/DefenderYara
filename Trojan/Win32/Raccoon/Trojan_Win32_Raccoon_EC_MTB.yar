
rule Trojan_Win32_Raccoon_EC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {39 f0 4e 89 30 2b f2 41 83 c0 04 41 41 83 ea 04 41 83 fa 00 } //00 00 
	condition:
		any of ($a_*)
 
}