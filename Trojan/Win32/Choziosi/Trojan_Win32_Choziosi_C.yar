
rule Trojan_Win32_Choziosi_C{
	meta:
		description = "Trojan:Win32/Choziosi.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_2 = {4a 00 41 00 42 00 6c 00 41 00 48 00 67 00 41 00 64 00 41 00 42 00 51 00 41 00 47 00 45 00 41 00 64 00 41 00 42 00 6f 00 41 00 43 00 41 00 41 00 50 00 51 00 41 00 67 00 41 00 43 00 49 00 41 00 } //2 JABlAHgAdABQAGEAdABoACAAPQAgACIA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}