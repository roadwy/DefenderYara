
rule Trojan_WinNT_Simda_gen_A{
	meta:
		description = "Trojan:WinNT/Simda.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4e 3c 03 ce 0f b7 51 14 57 0f b7 79 06 8d 54 0a 18 8b cf 2b ce 8d 4c 11 28 } //01 00 
		$a_01_1 = {63 00 5f 00 25 00 34 00 2e 00 34 00 78 00 25 00 64 00 2e 00 6e 00 6c 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}