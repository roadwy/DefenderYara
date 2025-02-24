
rule Trojan_BAT_Remcos_AYA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 30 32 33 43 72 79 70 74 73 44 6f 6e 65 5c 64 72 77 6b } //2 2023CryptsDone\drwk
		$a_00_1 = {66 00 69 00 6c 00 65 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 20 00 70 00 65 00 72 00 6d 00 61 00 6e 00 65 00 6e 00 74 00 6c 00 79 00 2e 00 20 00 50 00 72 00 6f 00 63 00 65 00 65 00 64 00 3f 00 } //1 files will be deleted permanently. Proceed?
		$a_01_2 = {65 78 70 6f 72 74 65 72 57 6f 72 6b 65 72 5f 52 75 6e 57 6f 72 6b 65 72 43 6f 6d 70 6c 65 74 65 64 } //1 exporterWorker_RunWorkerCompleted
		$a_01_3 = {6c 61 6d 65 45 78 65 44 6f 77 6e 6c 6f 61 64 53 69 74 65 } //1 lameExeDownloadSite
		$a_01_4 = {64 75 70 65 46 69 6e 64 65 72 57 6f 72 6b 65 72 } //1 dupeFinderWorker
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}