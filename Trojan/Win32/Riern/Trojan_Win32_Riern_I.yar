
rule Trojan_Win32_Riern_I{
	meta:
		description = "Trojan:Win32/Riern.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 14 39 32 d3 88 14 3e 47 3b 7c 90 01 02 0f 8c 90 00 } //1
		$a_00_1 = {8b 91 10 01 00 00 68 f2 0a 00 00 6a 40 ff d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}