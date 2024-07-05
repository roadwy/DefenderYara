
rule Trojan_Win32_StealC_STK_MTB{
	meta:
		description = "Trojan:Win32/StealC.STK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 f4 8b 45 dc 01 45 f4 8b 45 f4 33 45 f8 31 45 fc 8b 45 fc 29 45 ec 8d 4d f0 e8 90 01 04 4f 74 0b 8b 5d f0 8b 4d d8 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}