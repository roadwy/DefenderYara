
rule Trojan_Win32_Alureon_EA{
	meta:
		description = "Trojan:Win32/Alureon.EA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 53 53 53 8b 90 01 04 40 00 ff d0 68 33 2b 38 6a e8 90 01 04 50 e8 90 01 04 ff d0 83 f8 05 0f 84 90 01 01 00 00 00 83 f8 02 0f 85 90 01 01 00 00 00 80 7c 24 90 01 01 61 0f 84 90 01 01 00 00 00 33 c0 e9 90 01 02 00 00 6a 40 68 00 30 00 00 68 00 38 0b 00 53 8b 90 02 04 40 00 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}