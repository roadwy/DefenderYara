
rule Backdoor_BAT_Gantorpe_A{
	meta:
		description = "Backdoor:BAT/Gantorpe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 6e 69 71 75 65 20 42 6f 74 2e 65 78 65 } //1 Unique Bot.exe
		$a_02_1 = {55 6e 69 71 75 65 20 42 6f 74 [0-08] 4d 69 63 72 6f 73 6f 66 74 [0-08] 43 6f 70 79 72 69 67 68 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}