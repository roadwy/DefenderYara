
rule Backdoor_Win32_Agent_CAG{
	meta:
		description = "Backdoor:Win32/Agent.CAG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 71 6c 70 61 73 73 2e 64 69 63 } //01 00  sqlpass.dic
		$a_01_1 = {73 61 3a 70 40 73 73 77 30 72 64 } //01 00  sa:p@ssw0rd
		$a_01_2 = {43 6f 6d 70 75 74 65 72 20 4e 75 6d 62 65 72 73 3a 20 25 64 } //01 00  Computer Numbers: %d
		$a_03_3 = {28 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 29 90 02 10 28 53 51 4c 53 45 52 56 45 52 29 90 00 } //01 00 
		$a_01_4 = {3d 3d 3d 3d 77 65 6c 63 6f 6d 65 3d 3d 3d 3d } //01 00  ====welcome====
		$a_01_5 = {75 73 61 67 65 3a 25 73 20 20 20 49 50 20 20 70 6f 72 74 20 5b 70 72 6f 78 69 70 5d 20 5b 70 6f 72 74 5d 20 5b 6b 65 79 5d } //01 00  usage:%s   IP  port [proxip] [port] [key]
		$a_01_6 = {6e 65 77 5f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 74 6f 5f 62 6f 75 6e 63 65 28 29 3a } //00 00  new_connection_to_bounce():
		$a_00_7 = {5d 04 00 } //00 49 
	condition:
		any of ($a_*)
 
}