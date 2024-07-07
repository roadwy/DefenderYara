
rule Trojan_Win32_IcedId_PC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 2b c3 03 f9 05 90 01 04 81 ff 90 01 02 00 00 75 08 8d 74 29 90 01 01 8d 4c 01 90 01 01 8b 54 24 10 8b 5c 24 14 03 c6 03 c8 a1 90 01 04 8d 84 10 90 00 } //1
		$a_02_1 = {8b 38 8b d1 2b d5 81 c2 90 01 04 81 fe 90 01 04 75 0f bd 90 01 04 2b e9 8b cd 8b 2d 90 01 04 83 44 24 10 04 81 c7 dc 6b ee 01 89 38 8b c1 8b 0d 90 01 04 2b c2 83 c0 09 81 7c 24 10 90 01 02 00 00 a3 90 01 04 8d 4c 01 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}