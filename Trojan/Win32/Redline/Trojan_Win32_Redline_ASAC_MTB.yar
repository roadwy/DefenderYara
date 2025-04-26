
rule Trojan_Win32_Redline_ASAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d [0-04] 93 00 00 00 75 10 68 [0-04] 8d 44 24 74 50 ff 15 [0-04] 8d 44 24 18 e8 [0-04] ff 4c 24 1c 0f } //1
		$a_03_1 = {c1 ea 05 03 54 24 20 03 cd 33 d1 03 c6 33 d0 2b fa 8b cf c1 e1 04 81 3d [0-04] 8c 07 00 00 c7 05 [0-04] 00 00 00 00 89 4c 24 10 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}