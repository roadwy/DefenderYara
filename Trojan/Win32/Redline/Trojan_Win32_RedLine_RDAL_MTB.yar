
rule Trojan_Win32_RedLine_RDAL_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 03 45 e4 0f be 08 8b 45 e4 99 be 37 00 00 00 f7 fe 8b 45 08 0f be 04 10 6b c0 26 99 be 1d 00 00 00 f7 fe 83 e0 2b 33 c8 88 4d e3 0f be 4d e3 0f be 55 e3 03 ca 8b 45 0c 03 45 e4 88 08 0f be 4d e3 8b 55 0c 03 55 e4 0f be 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}