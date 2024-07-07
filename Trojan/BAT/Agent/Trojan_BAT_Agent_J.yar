
rule Trojan_BAT_Agent_J{
	meta:
		description = "Trojan:BAT/Agent.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 5f 00 00 0a 13 09 20 e8 03 00 00 13 0a 11 0a 8d 07 00 00 01 13 0c 11 08 11 0c 16 11 0a 6f 21 00 00 0a 25 26 13 0b 11 0b 16 } //2
		$a_01_1 = {28 3f 00 00 0a 25 26 28 40 00 00 0a 25 26 7d 0a 00 00 04 02 11 04 1f 14 9a 7d 0b 00 00 04 02 } //2
		$a_00_2 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //1 msnmsgr.exe
		$a_00_3 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_00_4 = {6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 } //1 op_Inequality
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}