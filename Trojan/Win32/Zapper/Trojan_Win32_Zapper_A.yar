
rule Trojan_Win32_Zapper_A{
	meta:
		description = "Trojan:Win32/Zapper.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 68 65 63 6b 61 6e 64 73 77 69 74 63 68 2e 63 6f 6d 2f 61 66 69 6c 65 2f 37 2e 65 78 65 } //1 https://checkandswitch.com/afile/7.exe
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 61 64 66 69 6c 65 73 2e 72 75 2f 6d 61 69 6e 2f 74 69 67 65 72 2e 65 78 65 } //1 https://adfiles.ru/main/tiger.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}