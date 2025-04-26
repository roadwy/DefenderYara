
rule Trojan_Win32_Vundo_IG{
	meta:
		description = "Trojan:Win32/Vundo.IG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_11_0 = {64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 66 00 68 00 6f 00 73 00 00 } //1
	condition:
		((#a_11_0  & 1)*1) >=1
 
}