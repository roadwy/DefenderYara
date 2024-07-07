
rule Trojan_Win32_Cariez_A{
	meta:
		description = "Trojan:Win32/Cariez.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 %s\Rundll32.exe %s,DllUnregisterServer
		$a_03_1 = {68 a1 84 00 00 e8 90 01 04 83 c4 04 90 00 } //1
		$a_01_2 = {6a 00 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 04 80 8d 04 80 c1 e0 05 50 68 00 10 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}