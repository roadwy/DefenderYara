
rule TrojanDownloader_O97M_Qakbot_PDP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 61 68 6c 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 30 66 36 65 41 7a 79 57 4c 55 4c 2f 4c 6b 6d 6e 2e 70 6e 67 } //1 sahlonline.com/0f6eAzyWLUL/Lkmn.png
		$a_01_1 = {66 61 70 72 6f 61 64 76 69 73 6f 72 73 2e 63 6f 6d 2f 76 74 66 4c 44 4a 76 79 46 35 67 2f 4c 6b 6d 6e 2e 70 6e 67 } //1 faproadvisors.com/vtfLDJvyF5g/Lkmn.png
		$a_01_2 = {74 72 75 63 6b 6d 61 74 65 2e 6f 72 67 2f 50 44 36 54 41 70 37 63 73 4f 2f 4c 6b 6d 6e 2e 70 6e 67 } //1 truckmate.org/PD6TAp7csO/Lkmn.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}