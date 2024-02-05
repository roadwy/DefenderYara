
rule Trojan_Win64_Metasploit_CRTD_MTB{
	meta:
		description = "Trojan:Win64/Metasploit.CRTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 49 c7 c1 40 00 00 00 49 c7 c0 00 30 00 00 48 c7 c2 00 10 00 00 48 33 c9 e8 27 10 00 00 48 c7 c1 00 10 00 00 48 be 41 10 00 40 01 00 00 00 48 8b f8 f3 a4 ff d0 48 33 c9 e8 01 10 00 00 50 41 59 4c 4f 41 44 3a 00 } //01 00 
		$a_01_1 = {50 41 59 4c 4f 41 44 } //00 00 
	condition:
		any of ($a_*)
 
}