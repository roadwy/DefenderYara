
rule Backdoor_Linux_CallMe_A{
	meta:
		description = "Backdoor:Linux/CallMe.A,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 72 69 74 65 54 6f 46 69 6c 65 3a 61 74 6f 6d 69 63 61 6c 6c 79 3a 00 64 69 63 74 69 6f 6e 61 72 79 57 69 74 68 4f 62 6a 65 63 74 73 41 6e 64 4b 65 79 73 3a } //4
		$a_01_1 = {2f 74 6d 70 2f 74 6d 70 41 64 64 72 65 73 73 62 6f 6f 6b 2e 76 63 66 } //2 /tmp/tmpAddressbook.vcf
		$a_01_2 = {25 73 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 2e 73 79 73 74 6d } //2 %s/Library/LaunchAgents/.systm
		$a_01_3 = {2f 74 6d 70 2f 5f 5f 73 79 73 74 65 6d } //2 /tmp/__system
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}