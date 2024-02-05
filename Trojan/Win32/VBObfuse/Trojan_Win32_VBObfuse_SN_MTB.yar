
rule Trojan_Win32_VBObfuse_SN_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.SN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 34 17 3d 1b df c1 05 66 f7 c3 a8 f7 5b 66 a9 a2 50 66 81 fb a8 0f 31 f3 66 f7 c3 33 9c 66 a9 d6 b4 01 1c 10 f7 c2 da e7 46 41 66 81 fb e4 59 83 c2 04 66 3d 18 38 66 81 fb ef bb 81 fa 04 3c 00 00 75 } //01 00 
		$a_01_1 = {ff 34 17 f7 c7 c4 73 9c 34 f7 c7 f7 e1 c8 4d 5b 66 81 ff 84 91 f7 c2 a2 54 2b 18 31 f3 3d d0 9b 27 b1 f7 c2 03 2e 2b e0 01 1c 10 66 81 fa a2 ef 81 fb 60 84 b8 ef 83 c2 04 f7 c3 3b 08 a5 85 a9 44 ea 3f 78 81 fa 7c 3d 00 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}