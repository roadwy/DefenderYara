
rule Trojan_Win32_Zusy_ASD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 d3 8d 92 3f bf 1f d3 3a c8 81 f2 6d 0d 93 35 f8 f7 d2 81 ea 42 3d ce 2b d1 ca f5 81 c2 2c 0e 24 31 e9 } //02 00 
		$a_01_1 = {57 65 42 a1 fa 09 f8 61 6c 39 ff 16 d6 68 f6 8f 40 58 f1 f8 e3 cd 95 66 75 fd 92 11 cf ac 9b 88 59 9c 9c ff c8 81 23 6f 5e b1 24 18 e4 e0 2d 81 72 d0 2a f6 d1 45 4e 68 47 75 49 1f fd 24 40 } //01 00 
		$a_01_2 = {40 03 00 00 2e 00 00 00 00 00 00 5e 16 2f 00 00 10 00 00 00 50 03 } //00 00 
	condition:
		any of ($a_*)
 
}