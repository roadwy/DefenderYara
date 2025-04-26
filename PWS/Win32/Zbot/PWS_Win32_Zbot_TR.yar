
rule PWS_Win32_Zbot_TR{
	meta:
		description = "PWS:Win32/Zbot.TR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 72 21 2a 00 70 72 53 2a 00 70 17 28 47 00 00 06 72 6b 2a 00 70 72 9d 2a 00 70 17 28 47 00 00 06 28 09 00 00 2b 14 11 0a 11 17 11 17 } //1
		$a_01_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 31 33 33 37 5c 42 75 72 65 61 75 5c } //1 C:\Documents and Settings\1337\Bureau\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}