
rule Backdoor_Win64_Swoorp_A{
	meta:
		description = "Backdoor:Win64/Swoorp.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 30 30 70 65 72 70 34 73 73 77 30 72 64 } //01 00  s00perp4ssw0rd
		$a_01_1 = {70 34 73 73 77 30 72 64 } //01 00  p4ssw0rd
		$a_01_2 = {53 74 61 72 74 4a 61 76 61 53 63 72 69 70 74 3d } //01 00  StartJavaScript=
		$a_01_3 = {2f 63 67 69 2d 62 69 6e 2f 73 32 2e 63 67 69 } //01 00  /cgi-bin/s2.cgi
		$a_01_4 = {43 61 6e 6e 6f 74 20 64 6f 77 6e 6c 6f 61 64 3a } //00 00  Cannot download:
		$a_01_5 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}