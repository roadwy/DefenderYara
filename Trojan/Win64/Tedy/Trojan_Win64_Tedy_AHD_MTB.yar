
rule Trojan_Win64_Tedy_AHD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 77 65 62 72 61 74 53 65 72 76 69 63 65 } //10 main.webratService
		$a_01_1 = {6d 61 69 6e 2e 61 64 64 53 65 6c 66 54 6f 45 78 63 6c 75 73 69 6f 6e 73 } //20 main.addSelfToExclusions
		$a_01_2 = {6d 61 69 6e 2e 69 73 41 67 67 72 65 73 73 69 76 65 41 6c 72 65 61 64 79 49 6e 73 74 61 6c 6c 65 64 } //30 main.isAggressiveAlreadyInstalled
		$a_01_3 = {6d 61 69 6e 2e 68 69 64 65 53 65 6c 66 46 69 6c 65 73 } //40 main.hideSelfFiles
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}