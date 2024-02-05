
rule DDoS_Win32_Zanich_D{
	meta:
		description = "DDoS:Win32/Zanich.D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 20 25 73 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 44 65 63 6c 69 65 6e 74 2e 65 78 65 00 } //01 00 
		$a_01_1 = {52 65 66 6c 57 6f 72 6b 41 73 73 69 73 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}