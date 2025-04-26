
rule Trojan_Win32_Redline_ASAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 84 1c 20 01 00 00 88 84 3c 20 01 00 00 88 8c 1c 20 01 00 00 0f b6 84 3c 20 01 00 00 03 c2 0f b6 c0 0f b6 84 04 20 01 00 00 30 86 [0-04] 46 81 fe [0-04] 72 } //1
		$a_01_1 = {8a 8c 3c 20 01 00 00 0f b6 d1 03 da 81 e3 ff 00 00 80 79 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}