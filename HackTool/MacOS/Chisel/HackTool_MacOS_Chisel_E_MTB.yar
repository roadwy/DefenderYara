
rule HackTool_MacOS_Chisel_E_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 38 48 89 d7 48 8b 05 a5 b0 56 00 48 8b 00 48 89 45 d0 ff 15 98 b1 56 00 49 89 c6 0f 28 05 7e 54 55 00 0f 29 45 b0 c7 45 c0 03 00 00 00 48 8b 35 44 4c 58 00 48 8d 15 7d cc 56 00 48 89 c7 ff 15 54 b1 56 00 84 c0 } //1
		$a_01_1 = {45 0f b6 44 07 79 45 0f b6 4c 07 7a 45 0f b6 54 07 7b 45 0f b6 5c 07 7c 41 0f b6 5c 07 7d 48 8b 35 5e 4a 58 00 48 83 ec 08 48 8d 15 9b ce 56 00 4c 8b 2d 74 af 56 00 31 c0 53 41 53 41 52 41 ff d5 48 83 c4 20 48 89 c7 e8 e0 41 55 00 49 89 c4 4c 89 ff e8 d7 3f 55 00 48 8b 35 c4 4a 58 00 4c 89 e7 41 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}