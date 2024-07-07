
rule TrojanDownloader_O97M_Qakbot_PDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 74 65 72 6d 61 73 6c 6f 73 70 6f 7a 6f 6e 65 73 2e 63 6f 6d 2f 69 7a 34 6f 51 6e 5a 6b 51 6f 34 58 2f 31 2e 70 6e 22 26 22 67 } //1 ://termaslospozones.com/iz4oQnZkQo4X/1.pn"&"g
		$a_01_1 = {3a 2f 2f 6e 69 6c 6f 70 65 72 61 2e 6d 6c 2f 62 4a 68 4c 52 50 48 53 53 66 6d 34 2f 31 2e 70 6e 22 26 22 67 } //1 ://nilopera.ml/bJhLRPHSSfm4/1.pn"&"g
		$a_01_2 = {3a 2f 2f 68 65 61 6c 74 68 79 77 61 79 6c 61 62 2e 69 6e 2f 50 78 76 50 6c 43 6e 32 6c 69 57 70 2f 31 2e 70 6e 22 26 22 67 } //1 ://healthywaylab.in/PxvPlCn2liWp/1.pn"&"g
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}