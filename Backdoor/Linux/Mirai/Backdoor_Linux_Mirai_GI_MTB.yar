
rule Backdoor_Linux_Mirai_GI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 10 43 00 10 00 44 8c 65 58 03 24 08 00 02 24 02 00 c3 a4 10 00 04 ae 0c 00 a2 a0 0d 00 a0 a0 26 00 02 8e 0f ff 04 24 24 10 44 00 f0 ff 03 24 40 00 42 34 24 10 43 00 05 00 42 34 26 00 02 ae 58 00 a4 8f } //01 00 
		$a_03_1 = {21 28 20 02 21 30 00 02 09 f8 20 03 21 90 01 01 40 00 10 00 bc 8f 0b 90 01 03 21 18 40 02 21 20 53 02 f0 ff 05 24 00 00 62 90 01 01 00 00 00 00 26 10 45 00 1a 00 42 38 00 00 62 a0 01 00 63 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}