
rule Trojan_Win32_Androm_DA_MTB{
	meta:
		description = "Trojan:Win32/Androm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 90 02 04 59 90 02 04 46 90 02 04 8b 17 90 02 04 31 f2 66 90 01 04 39 ca 75 90 01 01 90 02 20 b9 90 01 04 90 02 06 83 e9 04 90 02 04 8b 14 0f 90 02 04 56 90 02 04 33 14 24 90 02 04 5e 90 02 04 89 14 08 90 02 04 83 f9 00 7f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}