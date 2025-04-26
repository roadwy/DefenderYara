
rule Trojan_BAT_Jortklaz_A{
	meta:
		description = "Trojan:BAT/Jortklaz.A,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 74 2d 72 6f 6b 6c 61 7a 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 54 65 73 74 73 5c 54 72 6f 6a 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 54 72 6f 6a 2e 70 64 62 } //20 C:\Users\t-roklaz\Documents\Visual Studio 2015\Projects\Tests\Troj\obj\Release\Troj.pdb
		$a_01_1 = {54 72 6f 6a 2e 65 78 65 } //10 Troj.exe
		$a_01_2 = {57 72 6f 74 65 20 74 6f 20 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 2e 65 78 65 20 6d 65 6d 6f 72 79 } //10 Wrote to RuntimeBroker.exe memory
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}