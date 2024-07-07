
rule Trojan_Win32_RedLine_DSD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 f7 8a 1c 06 02 d3 88 55 13 0f b6 d2 0f b6 0c 02 88 0c 06 88 1c 02 0f b6 0c 06 0f b6 d3 03 d1 0f b6 ca 8b 55 08 0f b6 0c 01 30 0c 17 47 8a 55 13 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}