
rule DDoS_Linux_Gafgyt_YA_MTB{
	meta:
		description = "DDoS:Linux/Gafgyt.YA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {3c 4e 65 77 53 74 61 74 75 73 55 52 4c 3e 24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 00 } //01 00 
		$a_00_1 = {50 4f 53 54 20 2f 63 74 72 6c 74 2f 44 65 76 69 63 65 55 70 67 72 61 64 65 5f 31 } //00 00  POST /ctrlt/DeviceUpgrade_1
	condition:
		any of ($a_*)
 
}