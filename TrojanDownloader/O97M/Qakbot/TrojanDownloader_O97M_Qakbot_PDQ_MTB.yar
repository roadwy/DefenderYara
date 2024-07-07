
rule TrojanDownloader_O97M_Qakbot_PDQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 74 63 6f 6e 6a 73 63 2e 63 6f 6d 2f 54 42 46 51 73 4a 69 56 41 76 2f 50 6d 6e 68 66 2e 70 6e 67 } //1 intconjsc.com/TBFQsJiVAv/Pmnhf.png
		$a_01_1 = {6b 74 64 2d 61 75 74 6f 2e 63 6f 6d 2f 76 4e 51 45 67 4b 77 55 77 74 69 38 2f 50 6d 6e 68 66 2e 70 6e 67 } //1 ktd-auto.com/vNQEgKwUwti8/Pmnhf.png
		$a_01_2 = {65 6e 6f 6b 74 65 78 74 69 6c 65 2e 63 6f 6d 2f 68 6a 65 42 72 42 77 4d 64 59 2f 50 6d 6e 68 66 2e 70 6e 67 } //1 enoktextile.com/hjeBrBwMdY/Pmnhf.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}