
rule TrojanDownloader_O97M_Emotet_RVR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 77 77 77 2e 63 68 61 73 69 6e 67 6d 61 76 65 72 69 63 6b 73 2e 63 6f 2e 6b 65 2f 61 67 65 6e 64 61 61 66 72 69 6b 61 64 65 62 61 74 65 73 2e 63 6f 2e 6b 65 2f 51 7a 6e 4f 46 4d 4b 56 39 52 2f 22 2c 22 } //01 00  //www.chasingmavericks.co.ke/agendaafrikadebates.co.ke/QznOFMKV9R/","
		$a_01_1 = {2f 2f 77 77 77 2e 62 75 64 64 79 6d 6f 72 65 6c 2e 63 6f 6d 2f 41 6f 4e 67 68 63 75 49 63 36 71 37 42 45 4b 70 34 2f 22 2c 22 } //01 00  //www.buddymorel.com/AoNghcuIc6q7BEKp4/","
		$a_01_2 = {2f 2f 62 73 62 6d 61 6b 69 6e 61 2e 63 6f 6d 2e 74 72 2f 6c 6f 67 6f 2f 65 56 57 61 41 57 6d 2f 22 2c 22 } //01 00  //bsbmakina.com.tr/logo/eVWaAWm/","
		$a_01_3 = {2f 2f 62 75 72 65 61 75 69 6e 74 65 72 6e 61 63 69 6f 6e 61 6c 2e 63 6f 6d 2e 61 72 2f 63 6f 6e 74 61 64 6f 72 2d 61 6e 61 6c 69 73 74 61 2d 70 72 6f 79 65 63 74 6f 73 2f 32 77 2f 22 2c 22 } //01 00  //bureauinternacional.com.ar/contador-analista-proyectos/2w/","
		$a_01_4 = {2f 2f 77 77 77 2e 76 61 6c 79 76 61 6c 2e 63 6f 6d 2f 70 75 6e 2f 56 41 59 4c 2f 22 2c 22 } //01 00  //www.valyval.com/pun/VAYL/","
		$a_01_5 = {2f 2f 63 61 62 61 6e 73 2e 63 6f 6d 2f 43 65 75 64 57 59 52 51 45 7a 5a 67 72 48 50 63 49 2f 22 2c 22 } //01 00  //cabans.com/CeudWYRQEzZgrHPcI/","
		$a_01_6 = {2f 2f 63 61 6c 7a 61 64 6f 79 75 79 69 6e 2e 63 6f 6d 2f 63 67 6a 2d 62 69 6e 2f 6a 5a 50 66 66 2f 22 2c 22 } //01 00  //calzadoyuyin.com/cgj-bin/jZPff/","
		$a_01_7 = {2f 2f 63 61 67 72 61 6e 75 73 2e 63 6f 6d 2f 73 6c 69 64 65 2f 6d 63 71 41 46 75 4d 68 61 65 6b 6e 2f 22 2c 22 } //01 00  //cagranus.com/slide/mcqAFuMhaekn/","
		$a_01_8 = {2f 2f 61 65 73 69 61 66 72 69 71 75 65 2e 63 6f 6d 2f 61 7a 65 72 74 79 2f 58 69 75 66 30 77 55 66 76 31 79 6c 2f 22 2c 22 } //01 00  //aesiafrique.com/azerty/Xiuf0wUfv1yl/","
		$a_01_9 = {2f 2f 77 77 77 2e 61 67 65 6e 74 6f 66 66 69 63 65 74 65 73 74 2e 63 6f 6d 2f 55 70 6c 6f 61 64 73 2f 67 79 46 30 69 32 58 2f 22 2c 22 } //01 00  //www.agentofficetest.com/Uploads/gyF0i2X/","
		$a_01_10 = {2f 2f 77 77 77 2e 63 61 62 69 6e 65 74 2d 70 73 79 63 68 65 2e 63 6f 6d 2f 65 43 4d 64 67 71 65 43 39 6a 6a 45 2f 22 2c 22 } //01 00  //www.cabinet-psyche.com/eCMdgqeC9jjE/","
		$a_01_11 = {2f 2f 63 61 62 62 71 73 75 70 70 6c 79 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 4f 63 54 74 2f 22 2c 22 } //00 00  //cabbqsupply.com/wp-content/OcTt/","
	condition:
		any of ($a_*)
 
}