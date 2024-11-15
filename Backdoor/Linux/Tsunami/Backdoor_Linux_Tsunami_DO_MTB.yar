
rule Backdoor_Linux_Tsunami_DO_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 45 ec 01 8b 45 ec 48 63 d8 48 8b 45 e0 48 89 c7 e8 ?? ?? ?? ?? 48 39 c3 73 ?? 8b 45 ec 48 63 d0 48 8b 45 e0 48 01 d0 0f b6 00 3c 20 } //1
		$a_03_1 = {8b 45 cc 48 98 48 c1 e0 04 48 05 40 95 60 00 48 8b 00 ?? ?? ?? ?? ?? ?? ?? 48 89 d6 48 89 c7 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 45 cc 48 98 48 c1 e0 04 48 05 40 95 60 00 48 8b 40 08 8b 0d 4c 31 20 00 48 8b 55 d0 48 8d b5 10 02 fe ff 89 cf } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}