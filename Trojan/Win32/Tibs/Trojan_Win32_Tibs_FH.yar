
rule Trojan_Win32_Tibs_FH{
	meta:
		description = "Trojan:Win32/Tibs.FH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 87 d1 5a 8d 1d 90 01 02 40 00 29 d2 8b 3b 52 ff d7 69 c0 00 00 01 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}