
rule PWS_Win32_Elivoco_A{
	meta:
		description = "PWS:Win32/Elivoco.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d8 85 db 7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 a3 67 fb ff } //1
		$a_01_1 = {8b 45 f4 c6 40 1d 00 8b 55 f8 8b 45 f4 8b 08 } //1
		$a_01_2 = {8b 55 bc 8b 45 e8 8b 08 ff 51 38 ff 45 e4 4e 75 c9 8b c3 } //1
		$a_01_3 = {4c 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 } //1 Live.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}