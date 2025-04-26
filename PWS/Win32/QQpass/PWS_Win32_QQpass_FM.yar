
rule PWS_Win32_QQpass_FM{
	meta:
		description = "PWS:Win32/QQpass.FM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 18 45 c6 44 24 19 64 c6 44 24 1a 69 c6 44 24 1b 74 } //10
		$a_03_1 = {6a 64 68 c8 00 00 00 6a 32 aa 6a 64 8d 54 ?? ?? 68 00 00 01 00 } //1
		$a_00_2 = {5c 54 4d 5c 52 65 67 69 73 74 72 79 2e 64 62 } //1 \TM\Registry.db
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}