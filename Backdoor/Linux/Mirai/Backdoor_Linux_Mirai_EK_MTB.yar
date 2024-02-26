
rule Backdoor_Linux_Mirai_EK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {7f e0 fe 70 83 81 00 10 7c 03 fa 78 83 a1 00 14 7c 63 00 50 80 01 00 24 7c 63 fe 70 83 e1 00 1c 7f c3 18 38 7c 08 03 a6 83 c1 00 18 38 21 00 20 } //02 00 
		$a_01_1 = {7c 08 02 a6 94 21 ff f0 93 e1 00 0c 7c 7f 1b 78 90 01 00 14 88 03 00 00 38 60 00 01 2f 80 00 00 41 9e 00 1c 7f e9 fb 78 } //00 00 
	condition:
		any of ($a_*)
 
}