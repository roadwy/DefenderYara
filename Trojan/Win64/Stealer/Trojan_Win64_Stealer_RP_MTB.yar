
rule Trojan_Win64_Stealer_RP_MTB{
	meta:
		description = "Trojan:Win64/Stealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 50 50 44 41 54 41 00 5c 68 74 64 6f 63 73 5c 00 00 00 00 00 00 00 00 5c 6f 75 74 70 75 74 2e 65 78 65 00 5c 00 00 00 43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 49 3a 5c 00 5a 3a 5c } //1
		$a_01_1 = {5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //1 \ConsoleApplication1.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}