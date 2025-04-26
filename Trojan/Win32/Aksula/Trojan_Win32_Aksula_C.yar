
rule Trojan_Win32_Aksula_C{
	meta:
		description = "Trojan:Win32/Aksula.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 53 61 4b 75 4c 61 20 4b 65 79 6d 61 6b 65 5c } //5 SOFTWARE\SaKuLa Keymake\
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 75 72 6c 2e 64 6c 6c 2c 46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //1 rundll32.exe url.dll,FileProtocolHandler
		$a_00_2 = {ff 15 38 a0 40 00 90 90 90 90 39 65 e8 74 0d 68 06 00 00 00 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_00_2  & 1)*3) >=9
 
}