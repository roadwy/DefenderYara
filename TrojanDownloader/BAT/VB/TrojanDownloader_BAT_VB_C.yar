
rule TrojanDownloader_BAT_VB_C{
	meta:
		description = "TrojanDownloader:BAT/VB.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 20 00 64 00 6f 00 20 00 41 00 64 00 6f 00 62 00 65 00 20 00 46 00 6c 00 61 00 73 00 68 00 20 00 50 00 6c 00 61 00 79 00 65 00 72 00 } //2 Instalador do Adobe Flash Player
		$a_01_1 = {5c 41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 2e 70 64 62 } //3 \Adobe Flash Player.pdb
		$a_01_2 = {37 00 34 00 34 00 3b 00 20 00 33 00 31 00 31 00 } //3 744; 311
		$a_01_3 = {41 64 6f 62 65 5f 46 6c 61 73 68 5f 50 6c 61 79 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //4 Adobe_Flash_Player.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=12
 
}