
rule Trojan_Win32_RedLine_RDAW_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 88 90 01 04 32 0c 33 0f b6 1c 33 8d 04 19 8b 4d d0 88 04 31 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}