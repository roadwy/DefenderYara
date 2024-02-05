
rule Trojan_Win32_Fareit_HDFG_MTB{
	meta:
		description = "Trojan:Win32/Fareit.HDFG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 9a 0b 28 85 99 0b 12 85 99 0b 2c 85 9b 0b 12 85 9b 0b 17 85 a5 0b 16 85 a1 0b 16 85 a3 0b 2a 85 a4 0b 16 85 a6 0b 29 85 9b 0b 2a 85 a0 0b 28 85 a5 0b 15 85 9c 0b 28 85 a3 0b 14 85 a5 0b 13 85 9a 0b 13 85 98 0b 2c 85 a5 0b 28 85 } //00 00 
	condition:
		any of ($a_*)
 
}