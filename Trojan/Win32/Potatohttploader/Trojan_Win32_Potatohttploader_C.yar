
rule Trojan_Win32_Potatohttploader_C{
	meta:
		description = "Trojan:Win32/Potatohttploader.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4a 75 69 63 79 50 6f 74 61 74 6f 2e 70 64 62 } //JuicyPotato.pdb  01 00 
		$a_80_1 = {43 4f 4d 20 2d 3e 20 73 65 6e 64 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a 20 25 64 } //COM -> send failed with error: %d  01 00 
		$a_80_2 = {43 4f 4d 20 2d 3e 20 72 65 63 76 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a 20 25 64 } //COM -> recv failed with error: %d  01 00 
		$a_80_3 = {5b 2b 5d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 20 4f 4b } //[+] CreateProcessAsUser OK  01 00 
		$a_80_4 = {73 68 75 74 64 6f 77 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a 20 25 64 } //shutdown failed with error: %d  00 00 
	condition:
		any of ($a_*)
 
}