
rule PWS_Win32_Lolyda_F{
	meta:
		description = "PWS:Win32/Lolyda.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 c0 74 27 33 ff 81 3c 37 23 fe 4e f7 75 11 83 7c 37 08 00 74 0a 81 7c 37 0c 84 14 1a af 74 2c 90 09 06 00 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}