
rule Trojan_Win32_Predator_PB_MTB{
	meta:
		description = "Trojan:Win32/Predator.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f be c8 81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8a 84 15 90 01 02 ff ff 2a c1 88 84 15 90 01 02 ff ff 42 89 95 90 01 02 ff ff 8a 85 90 01 02 ff ff eb cc 90 09 05 00 83 fa 90 01 01 73 90 00 } //01 00 
		$a_02_1 = {0f be c0 25 0f 00 00 80 79 05 48 83 c8 f0 40 28 44 0d 90 01 01 41 83 f9 90 01 01 73 05 8a 45 90 01 01 eb e2 90 00 } //01 00 
		$a_02_2 = {40 83 f8 0d 73 06 8a 4c 24 90 01 01 eb f0 90 09 04 00 30 4c 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}