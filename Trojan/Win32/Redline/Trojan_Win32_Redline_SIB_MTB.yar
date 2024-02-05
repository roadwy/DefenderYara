
rule Trojan_Win32_Redline_SIB_MTB{
	meta:
		description = "Trojan:Win32/Redline.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 8c 3f 90 01 04 f3 0f 6f 94 3f 90 01 04 66 0f db d0 66 0f db c8 66 0f 67 ca f3 0f 7f 0c 3b 83 c7 90 01 01 81 ff 90 01 04 75 90 01 01 a0 90 01 04 8a 0d 90 01 04 8a 15 90 01 04 8d 7e 90 01 01 88 83 90 01 04 88 8b 90 01 04 8a 0d 90 01 04 88 93 90 01 04 8a 15 90 01 04 88 8b 90 01 04 8a 0d 90 01 04 88 93 90 01 04 8a 15 90 01 04 88 8b 90 00 } //01 00 
		$a_03_1 = {89 f0 81 e6 90 01 04 f7 d0 89 c1 09 f8 83 e1 90 01 01 f7 d0 09 ce 89 f9 83 e7 90 01 01 f7 d1 81 e1 90 01 04 09 f9 bf 90 01 04 31 f1 8b 75 90 01 01 09 c8 8b 4d 90 01 01 88 01 31 c9 8a 45 90 01 01 28 c1 b0 90 01 01 28 c8 b1 90 01 01 b5 90 01 01 28 c1 b0 90 01 01 28 c8 28 c5 b0 90 01 01 28 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}