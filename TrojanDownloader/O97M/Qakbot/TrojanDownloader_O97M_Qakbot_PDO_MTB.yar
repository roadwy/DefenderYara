
rule TrojanDownloader_O97M_Qakbot_PDO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 52 6c 4d 6f 6e 90 02 03 72 65 90 02 03 67 73 76 90 02 03 72 33 32 90 00 } //1
		$a_01_1 = {43 3a 5c 4d 65 72 74 6f 5c 42 79 72 6f 73 74 5c 56 65 6f 6e 73 65 2e 4f 4f 4f 43 43 43 58 58 58 } //1 C:\Merto\Byrost\Veonse.OOOCCCXXX
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}