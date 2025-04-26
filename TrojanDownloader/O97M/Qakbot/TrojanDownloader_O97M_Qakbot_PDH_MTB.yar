
rule TrojanDownloader_O97M_Qakbot_PDH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 64 67 75 63 6f 6e 73 75 6c 74 2e 63 6f 6d 2f 6c 65 36 57 53 67 55 44 58 52 4f 2f 56 66 6e 62 47 2e 70 6e 67 } //1 ://dguconsult.com/le6WSgUDXRO/VfnbG.png
		$a_01_1 = {3a 2f 2f 70 61 67 61 72 62 65 74 6f 6e 2e 63 6f 6d 2f 6b 7a 43 49 33 4e 57 47 7a 2f 56 66 6e 62 47 2e 70 6e 67 } //1 ://pagarbeton.com/kzCI3NWGz/VfnbG.png
		$a_01_2 = {3a 2f 2f 6a 6b 69 70 6c 2e 69 6e 2f 4e 4f 4f 64 68 65 62 38 2f 56 66 6e 62 47 2e 70 6e 67 } //1 ://jkipl.in/NOOdheb8/VfnbG.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}