
rule Trojan_Win32_Zloader_SIBG_MTB{
	meta:
		description = "Trojan:Win32/Zloader.SIBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 55 90 01 01 90 02 a0 0f b6 4d 90 1b 00 2b 8d 90 01 04 88 4d 90 1b 00 90 02 f0 8a 45 90 1b 00 8a 8d 90 1b 03 d2 c0 88 45 90 1b 00 90 02 70 8b 85 90 01 04 8a 4d 90 1b 00 88 08 90 02 c0 8b 85 90 01 04 83 c0 90 01 01 89 85 90 1b 0d 90 02 70 8b 85 90 1b 0a 83 c0 90 01 01 89 85 90 1b 0a 90 02 80 8b 8d 90 1b 03 c1 c1 90 01 01 89 8d 90 1b 03 90 02 e0 69 95 90 1b 03 90 01 04 89 95 90 1b 03 90 02 a0 8b 85 90 01 04 05 a7 22 00 00 89 85 90 1b 1d 90 02 c0 90 18 8b 95 90 1b 1d 3b 95 a8 fe ff ff 0f 8d 90 01 04 90 02 a0 8b 8d 90 1b 0d 8a 11 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}