
rule Trojan_Win32_RedLine_RDBB_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b f7 c1 ee 05 03 f5 8b 44 24 1c 31 44 24 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}