
rule PWS_Win32_Frethog_AC{
	meta:
		description = "PWS:Win32/Frethog.AC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 0b c0 75 1d e8 90 01 04 0b c0 74 14 6a 00 6a 04 6a 00 68 90 01 04 6a 00 6a 00 e8 90 00 } //2
		$a_01_1 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}