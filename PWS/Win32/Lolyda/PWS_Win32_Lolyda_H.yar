
rule PWS_Win32_Lolyda_H{
	meta:
		description = "PWS:Win32/Lolyda.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 85 e8 fe ff ff 50 68 90 01 04 e8 90 01 02 00 00 68 90 01 04 68 90 01 04 e8 90 01 02 00 00 68 90 01 04 68 90 01 04 ff 75 fc e8 90 01 02 00 00 0b c0 74 73 89 45 f8 50 ff 75 fc e8 90 01 02 00 00 89 45 f0 ff 75 f8 ff 75 fc e8 90 01 02 00 00 0b c0 74 55 50 e8 90 01 02 00 00 0b c0 74 4b 89 45 ec 6a 00 6a 20 6a 02 6a 00 6a 00 68 00 00 00 40 68 90 01 04 e8 90 01 02 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}