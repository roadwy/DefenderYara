
rule Worm_BAT_Nepinseft_A{
	meta:
		description = "Worm:BAT/Nepinseft.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3c 00 68 00 31 00 3e 00 4d 00 61 00 73 00 74 00 65 00 72 00 4b 00 65 00 79 00 20 00 4c 00 6f 00 67 00 73 00 20 00 6f 00 66 00 } //1 <h1>MasterKey Logs of
		$a_01_1 = {2d 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 50 00 43 00 2d 00 2d 00 2d 00 2d 00 } //1 -Information of Infected PC----
		$a_01_2 = {4e 00 65 00 77 00 20 00 50 00 43 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 } //1 New PC Infected
		$a_01_3 = {4d 61 73 74 65 72 4b 65 79 5f 53 74 75 62 2e 52 65 73 6f 75 72 63 65 73 } //1 MasterKey_Stub.Resources
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 68 00 61 00 74 00 69 00 73 00 6d 00 79 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 6e 00 30 00 39 00 32 00 33 00 30 00 39 00 34 00 35 00 2e 00 61 00 73 00 70 00 } //1 http://whatismyip.com/automation/n09230945.asp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}