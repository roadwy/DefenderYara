
rule PWS_Win32_Buroaf_A{
	meta:
		description = "PWS:Win32/Buroaf.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 00 90 02 04 77 77 77 2e 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 90 00 } //1
		$a_01_1 = {55 6e 68 61 6e 64 6c 65 64 20 45 78 63 65 70 74 69 6f 6e 20 30 78 38 30 30 34 30 37 } //1 Unhandled Exception 0x800407
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 73 00 6d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 72 00 75 00 } //1 http://gsmdefender.ru
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}