
rule TrojanDownloader_Win64_Tedy_CP_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tedy.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f } //2 https://files.catbox.moe/
		$a_01_1 = {53 74 6f 70 20 49 6e 74 65 72 6e 65 74 } //2 Stop Internet
		$a_01_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 61 6c 6c 20 70 72 6f 67 72 61 6d 3d } //2 netsh advfirewall firewall delete rule name=all program=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}