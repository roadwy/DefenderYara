
rule Trojan_WinNT_Bagle_gen_D{
	meta:
		description = "Trojan:WinNT/Bagle.gen!D,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 57 49 4e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 5c 5c 2e 5c 00 53 6f 66 74 77 61 72 65 5c 62 69 73 6f 66 74 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 00 53 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}