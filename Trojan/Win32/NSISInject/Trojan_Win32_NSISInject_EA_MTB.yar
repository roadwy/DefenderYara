
rule Trojan_Win32_NSISInject_EA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 } //01 00 
		$a_03_1 = {88 04 39 41 3b cb 72 90 01 01 6a 00 6a 00 57 ff 15 90 01 04 f7 d0 81 ea 1f 96 00 00 81 eb cd 16 01 00 bb c3 6c 00 00 35 96 24 01 00 f7 d2 43 59 c2 90 00 } //01 00 
		$a_03_2 = {88 04 39 41 3b cb 72 90 01 01 6a 00 6a 00 57 ff 15 90 01 04 35 cd ce 00 00 81 e9 c2 fc 00 00 05 e9 5b 00 00 81 c2 24 c7 00 00 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}