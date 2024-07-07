
rule TrojanDownloader_Linux_PythonAgent_D_MTB{
	meta:
		description = "TrojanDownloader:Linux/PythonAgent.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 fd 48 81 c7 78 30 00 00 53 48 83 ec 08 ff 15 42 44 20 00 48 85 c0 0f 84 3a 01 00 00 48 89 c6 48 8d 3d 26 20 00 00 4c 8d 35 39 20 00 00 ff 15 52 44 20 00 48 8d 3d 1b 20 00 00 ff 15 b5 44 20 00 48 89 c7 ff 15 8c 44 20 00 48 8d 35 0d 20 00 00 48 89 c7 ff 15 dc 44 20 00 48 8b 5d 10 49 89 c5 48 3b 5d 18 } //1
		$a_01_1 = {48 8d 35 54 25 00 00 48 89 fb e8 90 dc ff ff 48 89 05 29 56 20 00 48 85 c0 0f 84 12 06 00 00 48 8d 35 4e 25 00 00 48 89 df e8 71 dc ff ff 48 89 05 02 56 20 00 48 85 c0 0f 84 19 06 00 00 48 8d 35 4c 25 00 00 48 89 df e8 52 dc ff ff 48 89 05 db 55 20 00 48 85 c0 0f 84 e7 05 00 00 48 8d 35 3b 25 00 00 48 89 df e8 33 dc ff ff 48 89 05 b4 55 20 00 48 85 c0 0f 84 01 06 00 00 48 8d 35 35 25 00 00 48 89 df e8 14 dc ff ff 48 89 05 8d 55 20 00 48 85 c0 0f 84 cf 05 00 00 48 8d 35 24 25 00 00 48 89 df e8 f5 db ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}