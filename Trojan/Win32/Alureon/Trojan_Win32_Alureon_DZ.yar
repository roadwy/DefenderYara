
rule Trojan_Win32_Alureon_DZ{
	meta:
		description = "Trojan:Win32/Alureon.DZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 6a 02 68 00 00 00 80 56 8b 05 90 01 02 40 00 ff d0 56 8b 90 02 04 40 00 ff d0 8b 90 02 03 3b c7 0f 85 90 01 01 00 00 00 57 ff 90 02 03 57 ff 90 02 03 e8 90 01 04 e9 90 01 01 00 00 00 83 f8 02 0f 84 90 01 01 00 00 00 3b c6 0f 85 90 01 01 00 00 00 f7 90 02 03 fe ff ff ff 0f 84 90 01 01 00 00 00 83 f8 03 0f 84 90 01 01 00 00 00 56 56 56 56 e8 90 01 04 50 8b 90 02 04 40 00 e9 90 01 01 00 00 00 6a 4d 6a 4d 6a 37 6a 2c 57 57 8b 90 02 04 40 00 ff d0 85 c0 0f 84 90 01 01 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}