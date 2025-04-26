
rule PWS_Win32_Hoopaki_A{
	meta:
		description = "PWS:Win32/Hoopaki.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 e9 8b 45 14 8b 5d fc 2b c3 83 e8 05 89 45 f5 8d 45 f4 6a 05 50 ff 75 fc e8 } //1
		$a_01_1 = {83 c6 32 81 fe f4 01 00 00 7c be } //1
		$a_01_2 = {2f 6c 69 6e 2e 61 73 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}