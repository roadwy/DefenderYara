
rule Trojan_BAT_Dorifel_AA_MTB{
	meta:
		description = "Trojan:BAT/Dorifel.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 16 00 00 00 58 00 00 00 a8 00 00 00 49 00 00 00 0b 00 00 00 01 00 00 00 03 } //10
		$a_81_1 = {53 75 70 70 72 65 73 73 49 6c 64 61 73 6d 41 74 74 72 69 62 75 74 65 } //3 SuppressIldasmAttribute
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //3 GetExecutingAssembly
		$a_81_3 = {49 73 4c 6f 67 67 69 6e 67 } //3 IsLogging
		$a_81_4 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //3 System.Runtime.InteropServices
		$a_81_5 = {67 65 74 5f 49 73 41 6c 69 76 65 } //3 get_IsAlive
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=25
 
}