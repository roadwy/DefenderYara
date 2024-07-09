
rule TrojanDropper_Win32_Chexct_A{
	meta:
		description = "TrojanDropper:Win32/Chexct.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 48 28 8b 90 90 0c 01 00 00 2b 88 04 01 00 00 8d 04 32 03 ca 8b d0 2b d1 89 84 24 ?? ?? 00 00 83 c2 ?? 89 54 24 ?? 8b d1 2b d0 8a 04 39 } //1
		$a_03_1 = {85 c6 44 24 ?? c0 c6 44 24 ?? 75 c6 44 24 ?? ?? c6 44 24 ?? 6a c6 44 24 ?? 0a c6 44 24 ?? 04 c6 44 24 ?? ?? c6 44 24 ?? 81 90 09 04 00 c6 44 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}