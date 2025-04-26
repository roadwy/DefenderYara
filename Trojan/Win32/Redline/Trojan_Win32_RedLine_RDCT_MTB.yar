
rule Trojan_Win32_RedLine_RDCT_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c3 fe c8 02 c3 88 04 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}