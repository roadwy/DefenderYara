
rule Trojan_Win32_Farfli_MAR_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {49 6e 69 74 45 6e 67 69 6e 65 } //01 00  InitEngine
		$a_03_1 = {0f ac da 11 ff 34 24 f6 d8 66 d3 d2 66 0f be d1 f8 5a c0 c0 06 68 90 01 04 30 c3 80 ca 4f 66 0f bd d0 0f b6 c0 66 f7 c2 40 2b 83 c4 08 0f 87 90 00 } //01 00 
		$a_01_2 = {83 ed 04 88 2c 24 89 45 00 c6 04 24 7e 88 0c 24 9c 8d 64 24 24 e9 } //00 00 
	condition:
		any of ($a_*)
 
}