
rule TrojanDownloader_O97M_AgentTesla_RVC_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {67 65 74 45 6e 75 6d 4e 61 6d 65 20 3d 20 22 20 68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f [0-14] 22 0d 0a 20 20 20 20 45 6e 64 20 53 65 6c 65 63 74 } //1
		$a_01_1 = {6d 79 76 61 6c 75 65 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 46 39 33 35 44 43 32 32 2d 31 43 46 30 2d 31 31 44 30 2d 41 44 42 39 2d 30 30 43 30 34 46 44 35 38 41 30 42 22 29 } //1 myvalue = GetObject("new:F935DC22-1CF0-11D0-ADB9-00C04FD58A0B")
		$a_01_2 = {62 6f 72 61 2e 20 5f 0d 0a 6d 79 76 61 6c 75 65 2e 20 5f 0d 0a 52 75 6e 20 6c 6f 72 61 32 } //1
		$a_01_3 = {6c 6f 72 61 32 20 3d 20 4e 61 6d 61 6b 42 6f 72 61 20 2b 20 6c 6f 72 61 } //1 lora2 = NamakBora + lora
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}