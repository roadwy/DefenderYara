
rule Trojan_Win64_Zusy_ABZS_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ABZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //DisableAntiSpyware  1
		$a_80_1 = {44 69 73 61 62 6c 65 41 6e 74 69 56 69 72 75 73 } //DisableAntiVirus  1
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
		$a_80_3 = {46 75 63 6b 20 79 6f 75 2c 20 61 73 73 68 6f 6c 65 2e } //Fuck you, asshole.  1
		$a_80_4 = {49 66 20 79 6f 75 20 64 6f 6e 27 74 20 6b 6e 6f 77 20 77 68 61 74 20 79 6f 75 27 72 65 20 64 6f 69 6e 67 2c 20 64 65 6c 65 74 65 20 74 68 65 20 76 69 72 75 73 20 6f 72 20 63 6c 69 63 6b } //If you don't know what you're doing, delete the virus or click  1
		$a_80_5 = {69 6c 6c 20 6d 61 6b 65 20 61 20 6c 6f 74 20 6f 66 20 6e 6f 69 73 65 20 61 6e 64 20 64 65 6c 65 74 65 20 79 6f 75 72 20 62 6f 6f 74 20 61 6e 64 20 73 79 73 74 65 6d 20 66 69 6c 65 73 } //ill make a lot of noise and delete your boot and system files  1
		$a_80_6 = {50 6c 65 61 73 65 20 63 6f 6e 66 69 72 6d 20 79 6f 75 72 20 62 65 68 61 76 69 6f 72 2e 20 54 68 69 73 20 69 73 20 79 6f 75 72 20 6c 61 73 74 20 63 68 61 6e 63 65 } //Please confirm your behavior. This is your last chance  1
		$a_80_7 = {48 61 68 61 68 61 2c 20 69 64 69 6f 74 2c 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 61 73 20 64 65 73 74 72 6f 79 65 64 2c 20 72 69 67 68 74 3f } //Hahaha, idiot, your computer was destroyed, right?  1
		$a_80_8 = {54 68 69 73 20 76 69 72 75 73 20 77 69 6c 6c 20 63 61 75 73 65 20 79 6f 75 20 67 72 65 61 74 20 74 72 6f 75 62 6c 65 } //This virus will cause you great trouble  1
		$a_80_9 = {68 61 68 61 68 61 2c 53 61 79 20 67 6f 6f 64 62 79 65 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //hahaha,Say goodbye to your computer  1
		$a_80_10 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //DisableRegistryTools  1
		$a_80_11 = {52 65 6c 65 61 73 65 5c 50 43 20 53 69 6d 75 6c 61 74 6f 72 33 2e 30 2e 70 64 62 } //Release\PC Simulator3.0.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=12
 
}