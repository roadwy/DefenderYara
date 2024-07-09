
rule PWS_Win32_QQpass_ET{
	meta:
		description = "PWS:Win32/QQpass.ET,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 30 80 f3 69 88 1c 30 40 3d ?? ?? ?? ?? 72 ef } //1
		$a_01_1 = {b9 80 23 00 00 81 c6 00 04 00 00 8b fb 83 c4 04 f3 a5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}