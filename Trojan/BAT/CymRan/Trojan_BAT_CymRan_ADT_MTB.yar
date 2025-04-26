
rule Trojan_BAT_CymRan_ADT_MTB{
	meta:
		description = "Trojan:BAT/CymRan.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {14 0a 16 0b 02 28 ?? 00 00 0a 2d 47 02 28 ?? 00 00 0a 2c 3d 02 73 79 00 00 0a 03 04 05 28 ?? 00 00 0a 25 0a 0c 06 16 6a 16 6a 6f ?? 00 00 0a 06 16 6a 16 6a 6f ?? 00 00 0a de 03 26 de 00 de 0a 08 2c 06 08 } //3
		$a_03_1 = {8d 10 00 00 01 25 16 02 7b 1d 00 00 04 a2 25 17 02 7b 19 00 00 04 a2 25 18 06 a2 25 19 28 ?? 00 00 0a a2 28 } //2
		$a_01_2 = {54 61 6d 69 72 41 62 75 53 61 6c 61 68 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 63 79 6d 75 6c 61 74 65 2d 73 63 65 6e 61 72 69 6f 2d 67 65 6e 65 72 61 74 6f 72 5c 45 78 65 63 75 74 6f 72 73 5c 43 79 6d 75 6c 61 74 65 54 61 73 6b 53 63 68 65 64 75 6c 65 72 5c 43 79 6d 75 6c 61 74 65 54 61 73 6b 53 63 68 65 64 75 6c 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 45 44 52 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 70 64 62 } //4 TamirAbuSalah\source\repos\cymulate-scenario-generator\Executors\CymulateTaskScheduler\CymulateTaskScheduler\obj\Release\EDRTaskScheduler.pdb
		$a_01_3 = {45 00 44 00 52 00 20 00 73 00 74 00 6f 00 70 00 73 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 } //1 EDR stops running
		$a_01_4 = {43 00 79 00 6d 00 75 00 6c 00 61 00 74 00 65 00 45 00 44 00 52 00 } //1 CymulateEDR
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}