
rule Trojan_Win32_Midie_SIBG3_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBG3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 00 00 00 00 8a 81 90 01 04 81 f9 90 01 04 74 90 01 01 90 02 20 34 90 01 01 2c 90 01 01 90 02 20 34 90 01 01 90 02 20 04 90 01 01 90 02 20 88 81 90 1b 00 83 c1 01 90 18 8a 81 90 1b 00 81 f9 90 1b 01 90 18 b0 00 b9 00 00 00 00 8d 45 90 01 01 50 6a 40 68 90 1b 01 68 90 1b 00 ff 15 90 01 04 b9 90 1b 00 ff d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}