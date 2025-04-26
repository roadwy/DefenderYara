
rule Trojan_Win64_PortStarter_A{
	meta:
		description = "Trojan:Win64/PortStarter.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {6d 61 78 20 70 6f 72 74 20 66 6f 72 20 6c 69 ?? 74 65 6e 20 74 6f } //2
		$a_03_1 = {6d 61 69 6e 2e 64 6c 6c 00 54 65 73 74 00 5f 63 67 6f 5f 64 75 6d 6d 79 ?? 65 78 70 6f 72 74 } //1
		$a_03_2 = {6b 75 69 4e 65 77 20 70 ?? 72 74 3a 20 25 73 0a } //1
	condition:
		((#a_02_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}