
rule Trojan_Win32_Emotet_DHI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c3 c1 e8 10 88 06 46 8b cb c1 e9 08 88 0e 46 88 1e 33 db 46 88 5d ff } //1
		$a_02_1 = {8b f1 c1 ee 05 03 35 90 01 04 8b f9 c1 e7 04 03 3d 90 01 04 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 05 03 35 90 01 04 8b f8 c1 e7 04 03 3d 90 01 04 33 f7 8d 3c 02 33 f7 2b ce 81 c2 90 01 04 83 6d fc 01 75 b6 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}