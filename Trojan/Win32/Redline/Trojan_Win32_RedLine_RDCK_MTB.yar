
rule Trojan_Win32_RedLine_RDCK_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 f7 74 24 10 8a 82 90 01 04 30 04 31 41 3b 4c 24 0c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}