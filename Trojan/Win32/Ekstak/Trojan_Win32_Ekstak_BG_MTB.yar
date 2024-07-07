
rule Trojan_Win32_Ekstak_BG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 ef 10 8a 07 b9 90 01 04 a2 90 01 04 a1 90 01 04 03 c8 47 8d 14 18 8b 45 0c 8a 0c 19 88 0c 02 8a 8b 90 01 04 84 c9 75 90 01 01 8b 15 90 01 04 8a 0d 90 01 04 03 d3 03 c2 30 08 83 3d 90 01 04 03 76 90 00 } //1
		$a_02_1 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 90 01 04 84 c9 75 90 01 01 8b 0d 90 01 04 8a 1d 90 01 04 03 c8 03 cf 30 19 39 15 90 01 04 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}