
rule Trojan_BAT_Mamson_CG_MTB{
	meta:
		description = "Trojan:BAT/Mamson.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 12 00 07 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 06 6f 43 ?? ?? 0a 03 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 26 2a } //10
		$a_80_1 = {4c 55 4e 43 48 45 52 20 43 52 41 43 4b 49 4e 47 } //LUNCHER CRACKING  3
		$a_80_2 = {72 75 6e 61 73 } //runas  3
		$a_80_3 = {45 78 65 63 75 74 65 41 73 41 64 6d 69 6e } //ExecuteAsAdmin  3
		$a_80_4 = {63 61 72 70 65 74 61 } //carpeta  3
		$a_80_5 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //get_StartupPath  3
		$a_80_6 = {4c 61 75 6e 63 68 65 72 2e 65 78 65 } //Launcher.exe  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=18
 
}