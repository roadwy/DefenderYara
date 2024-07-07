
rule Trojan_Win32_Vundo_U{
	meta:
		description = "Trojan:Win32/Vundo.U,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a be e0 26 52 36 d1 34 1e 0d 93 5f df fe cc ee 49 bd c2 b1 d7 6f 8d 09 a8 2e 08 71 37 5b 87 1a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}