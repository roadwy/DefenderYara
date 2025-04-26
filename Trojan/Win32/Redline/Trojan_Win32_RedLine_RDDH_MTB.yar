
rule Trojan_Win32_RedLine_RDDH_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f b6 02 35 a2 00 00 00 8b 4d 08 03 4d fc 88 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}