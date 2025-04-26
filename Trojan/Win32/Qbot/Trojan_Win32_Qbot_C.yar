
rule Trojan_Win32_Qbot_C{
	meta:
		description = "Trojan:Win32/Qbot.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 3a 5c 67 69 74 5c 67 6f 6f 67 6c 65 5c 70 75 62 6c 69 63 5c 64 6e 73 2e 50 44 42 } //1 k:\git\google\public\dns.PDB
		$a_01_1 = {53 6c 65 73 73 43 68 72 6f 6d 65 66 72 6f 6d } //1 SlessChromefrom
		$a_01_2 = {62 00 65 00 6e 00 65 00 66 00 69 00 74 00 7a 00 61 00 4f 00 33 00 74 00 68 00 65 00 73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 64 00 } //1 benefitzaO3thesandboxd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}