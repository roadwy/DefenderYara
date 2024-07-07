
rule Trojan_Win32_Narkean_A{
	meta:
		description = "Trojan:Win32/Narkean.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 11 8b 4d ec 8a 1c 08 80 c3 8f 88 1c 08 40 3b c2 7c ef b8 } //1
		$a_01_1 = {4f 63 65 61 6e 41 72 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}