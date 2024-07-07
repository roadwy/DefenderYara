
rule Trojan_Win32_DJVU_IP_MTB{
	meta:
		description = "Trojan:Win32/DJVU.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb c1 e1 04 03 4c 24 34 8b c3 c1 e8 05 03 44 24 2c 8d 14 2b 33 ca 89 44 24 18 89 4c 24 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}