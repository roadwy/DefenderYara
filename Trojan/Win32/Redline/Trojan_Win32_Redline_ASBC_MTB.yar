
rule Trojan_Win32_Redline_ASBC_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 7d f4 8b 4d f8 8d 04 3b 31 45 fc d3 ef 03 7d e0 81 3d 90 01 04 21 01 00 00 75 90 00 } //1
		$a_01_1 = {73 65 77 6f 6d 65 78 69 6b 69 6a 61 6c 6f 64 65 64 65 6c 65 76 65 20 73 6f 79 75 67 6f 6c 6f 72 61 63 69 20 79 61 6d 61 7a 69 64 } //1 sewomexikijalodedeleve soyugoloraci yamazid
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}