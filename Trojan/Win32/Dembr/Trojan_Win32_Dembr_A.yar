
rule Trojan_Win32_Dembr_A{
	meta:
		description = "Trojan:Win32/Dembr.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 4f 38 34 30 31 31 32 2d } //1 JO840112-
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 } //1 shutdown -r -t 0
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1 \\.\PhysicalDrive%d
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 70 61 73 76 63 2e 65 78 65 } //1 taskkill /F /IM pasvc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}