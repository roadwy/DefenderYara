
rule Trojan_Win32_RedLineStealer_NEF_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 0f b6 0d 90 01 04 8b 55 fc 03 55 08 0f b6 02 33 c1 8b 4d fc 03 4d 08 88 01 8b e5 5d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}