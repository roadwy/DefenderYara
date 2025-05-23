
rule Trojan_Win64_BlackCatInstaller_A{
	meta:
		description = "Trojan:Win64/BlackCatInstaller.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 00 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 00 43 72 65 61 74 65 46 69 6c 65 57 00 33 36 33 2e 73 79 73 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 6b 65 72 6e 65 6c 62 61 73 65 2e 64 6c 6c 00 00 42 00 49 00 4e 00 41 00 52 00 59 00 } //1
		$a_01_1 = {64 00 6c 00 6c 00 2c 00 44 00 6c 00 6c 00 4d 00 61 00 69 00 6e 00 00 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}