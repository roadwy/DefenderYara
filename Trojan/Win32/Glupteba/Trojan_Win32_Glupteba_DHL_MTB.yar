
rule Trojan_Win32_Glupteba_DHL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 f7 74 24 90 01 01 8a 99 90 01 04 0f be 82 90 01 04 0f b6 d3 03 c6 03 d0 81 e2 ff 00 00 00 81 3d 90 01 08 8b f2 89 35 90 01 04 75 90 00 } //1
		$a_02_1 = {8b 45 fc 8d 34 07 e8 90 01 04 30 06 83 6d fc 01 39 5d fc 7d ea 90 00 } //1
		$a_81_2 = {77 69 68 61 6b 69 77 61 68 69 73 61 72 69 } //1 wihakiwahisari
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}