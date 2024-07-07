
rule TrojanDropper_Win32_Chexct_A{
	meta:
		description = "TrojanDropper:Win32/Chexct.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 48 28 8b 90 90 0c 01 00 00 2b 88 04 01 00 00 8d 04 32 03 ca 8b d0 2b d1 89 84 24 90 01 02 00 00 83 c2 90 01 01 89 54 24 90 01 01 8b d1 2b d0 8a 04 39 90 00 } //1
		$a_03_1 = {85 c6 44 24 90 01 01 c0 c6 44 24 90 01 01 75 c6 44 24 90 01 02 c6 44 24 90 01 01 6a c6 44 24 90 01 01 0a c6 44 24 90 01 01 04 c6 44 24 90 01 02 c6 44 24 90 01 01 81 90 09 04 00 c6 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}