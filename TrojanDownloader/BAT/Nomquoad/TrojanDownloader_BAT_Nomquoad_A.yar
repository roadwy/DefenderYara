
rule TrojanDownloader_BAT_Nomquoad_A{
	meta:
		description = "TrojanDownloader:BAT/Nomquoad.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 65 00 73 00 61 00 6f 00 66 00 2e 00 65 00 64 00 75 00 2e 00 70 00 74 00 2f 00 74 00 65 00 6d 00 70 00 6c 00 61 00 74 00 65 00 73 00 2f 00 62 00 65 00 65 00 7a 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 5f 00 67 00 65 00 6e 00 65 00 72 00 61 00 6c 00 2f 00 78 00 6d 00 6c 00 2f 00 78 00 69 00 71 00 75 00 65 00 79 00 68 00 61 00 79 00 75 00 64 00 68 00 78 00 7a 00 7a 00 63 00 2e 00 65 00 78 00 65 00 } //1 http://www.esaof.edu.pt/templates/beez/images_general/xml/xiqueyhayudhxzzc.exe
		$a_01_1 = {6e 00 6f 00 6d 00 61 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 nomar.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}