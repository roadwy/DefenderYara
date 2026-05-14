
rule TrojanDownloader_Win64_Tedy_CQ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tedy.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 61 63 74 69 76 61 64 6f 20 49 6e 74 65 72 6e 65 74 21 } //2 Desactivado Internet!
		$a_01_1 = {41 63 74 69 76 61 64 6f 20 49 6e 74 65 72 6e 65 74 21 } //2 Activado Internet!
		$a_03_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 [0-0f] 22 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 62 6c 6f 63 6b 20 70 72 6f 67 72 61 6d 3d } //2
		$a_01_3 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d } //2 netsh advfirewall firewall delete rule name=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}