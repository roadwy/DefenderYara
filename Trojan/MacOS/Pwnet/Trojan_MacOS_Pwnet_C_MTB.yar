
rule Trojan_MacOS_Pwnet_C_MTB{
	meta:
		description = "Trojan:MacOS/Pwnet.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 7d d4 00 0f 9f c0 34 ff 24 01 0f b6 c8 48 63 d1 48 83 fa 00 0f 84 1f 00 00 00 48 8d 3d a8 0f 00 00 48 8d 35 ad 0f 00 00 ba 3a 00 00 00 48 8d 0d 18 10 00 00 } //01 00 
		$a_00_1 = {69 6e 6a 65 63 74 6f 72 } //01 00 
		$a_00_2 = {43 73 67 6f 2f 43 73 67 6f 20 43 68 65 61 74 73 2f 49 6e 6a 65 63 74 6f 72 73 2f 6f 73 78 69 6e 6a 2d 66 69 78 65 64 2d 6d 61 73 74 65 72 2f 6f 73 78 69 6e 6a 2f 6d 61 63 68 5f 69 6e 6a 65 63 74 2e 63 } //00 00 
	condition:
		any of ($a_*)
 
}