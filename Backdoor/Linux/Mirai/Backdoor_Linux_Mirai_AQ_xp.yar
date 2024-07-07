
rule Backdoor_Linux_Mirai_AQ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 6b 69 6c 6c 65 72 5d 20 46 69 6e 69 73 68 65 64 } //1 [killer] Finished
		$a_01_1 = {58 41 4e 41 58 20 42 6f 74 6e 65 74 } //1 XANAX Botnet
		$a_01_2 = {6d 48 6f 49 4a 50 71 47 52 53 54 55 56 57 58 4c } //1 mHoIJPqGRSTUVWXL
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_4 = {44 45 42 55 47 20 4d 4f 44 45 20 59 4f } //1 DEBUG MODE YO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}