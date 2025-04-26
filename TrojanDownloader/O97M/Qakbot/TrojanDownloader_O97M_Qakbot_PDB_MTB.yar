
rule TrojanDownloader_O97M_Qakbot_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 69 63 68 65 6c 6c 65 74 61 78 73 65 72 76 69 63 65 73 2e 63 6f 6d 2f 51 36 53 42 58 32 34 5a 48 53 4e 31 2f 34 2e 70 6e 67 } //1 ://michelletaxservices.com/Q6SBX24ZHSN1/4.png
		$a_01_1 = {3a 2f 2f 6e 6f 75 72 69 73 68 69 6e 67 68 61 6e 64 73 63 61 72 65 2e 63 6f 6d 2f 78 74 48 6e 54 67 35 33 54 2f 34 2e 70 6e 67 } //1 ://nourishinghandscare.com/xtHnTg53T/4.png
		$a_01_2 = {3a 2f 2f 74 6c 6e 65 74 77 6f 72 6b 69 6e 67 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 74 69 38 6f 61 51 61 43 4d 2f 34 2e 70 6e 67 } //1 ://tlnetworkingsolutions.com/ti8oaQaCM/4.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}