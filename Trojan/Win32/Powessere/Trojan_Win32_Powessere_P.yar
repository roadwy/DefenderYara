
rule Trojan_Win32_Powessere_P{
	meta:
		description = "Trojan:Win32/Powessere.P,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_02_1 = {28 00 28 00 67 00 70 00 20 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 29 00 2e 00 [0-20] 29 00 7c 00 49 00 45 00 58 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}