
rule Trojan_Win32_Zusy_ABRO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ABRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 6f 73 6f 69 67 72 73 69 6f 68 69 6f 6a 68 73 65 67 67 } //2 Aosoigrsiohiojhsegg
		$a_01_1 = {42 6f 73 64 67 69 6f 73 69 67 6a 73 65 77 69 68 6a 73 65 68 } //2 Bosdgiosigjsewihjseh
		$a_01_2 = {42 6f 73 67 6f 69 73 72 6f 69 67 77 73 6f 69 68 6a 65 68 65 } //2 Bosgoisroigwsoihjehe
		$a_01_3 = {4f 6f 69 65 6a 67 69 6f 77 73 65 6a 67 6f 69 73 6a 68 73 } //2 Ooiejgiowsejgoisjhs
		$a_01_4 = {66 6f 72 6b 35 2e 64 6c 6c } //2 fork5.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}