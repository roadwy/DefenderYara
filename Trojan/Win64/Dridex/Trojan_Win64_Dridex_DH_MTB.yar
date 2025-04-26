
rule Trojan_Win64_Dridex_DH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 70 52 36 7c 4d 4a 2e 70 64 62 } //ppR6|MJ.pdb  3
		$a_80_1 = {76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 49 4f 63 74 6f 62 65 72 4d 62 65 63 61 6d 65 50 6c 45 78 61 6d 70 6c 65 3a 77 69 6c 6c 32 35 2c } //vulnerabilitiesIOctoberMbecamePlExample:will25,  3
		$a_80_2 = {62 61 64 62 6f 79 49 72 65 6c 65 61 73 65 68 61 73 45 69 6e 73 70 65 63 74 6f 72 58 6f 66 41 63 69 64 31 41 75 74 6f 6d 61 74 69 63 } //badboyIreleasehasEinspectorXofAcid1Automatic  3
		$a_80_3 = {43 68 72 6f 6d 65 70 4c 70 67 74 68 65 72 65 61 66 74 65 72 2c 73 75 70 70 6f 72 74 65 64 63 68 65 65 73 65 77 68 69 6c 65 } //ChromepLpgthereafter,supportedcheesewhile  3
		$a_80_4 = {4a 65 74 4d 61 6b 65 4b 65 79 } //JetMakeKey  3
		$a_80_5 = {46 72 65 63 6f 67 6e 69 74 69 6f 6e 2e 41 6c 74 65 72 6e 61 74 69 76 65 6c 79 2c 62 65 66 6f 72 65 4f 51 51 } //Frecognition.Alternatively,beforeOQQ  3
		$a_80_6 = {74 79 68 61 72 73 65 6e 61 6c 31 31 32 32 33 33 } //tyharsenal112233  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}