
rule Trojan_Win32_Redline_CBEB_MTB{
	meta:
		description = "Trojan:Win32/Redline.CBEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 4c 24 1c 90 01 04 83 c4 0c 69 db 90 01 04 83 c5 04 8b c1 c1 e8 18 33 c1 69 c0 90 01 04 33 d8 89 44 24 10 83 ee 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}