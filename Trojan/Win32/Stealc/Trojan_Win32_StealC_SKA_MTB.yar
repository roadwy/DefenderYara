
rule Trojan_Win32_StealC_SKA_MTB{
	meta:
		description = "Trojan:Win32/StealC.SKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 8d 04 1f 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 ec 75 90 00 } //1
		$a_03_1 = {31 45 fc 8b fa d3 ef 03 7d dc 81 3d 90 01 04 21 01 00 00 75 10 68 90 01 04 56 56 ff 15 90 01 04 8b 55 f8 31 7d fc 2b 5d fc 8d 45 f0 e8 90 01 04 ff 4d e8 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}