
rule Trojan_Win64_RedParrot_B_dha{
	meta:
		description = "Trojan:Win64/RedParrot.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 4a 44 4b 20 36 34 2d 42 69 74 20 4d 69 6e 69 6d 61 6c 20 56 4d } //1 OpenJDK 64-Bit Minimal VM
		$a_01_1 = {3a 20 74 68 69 73 20 6f 62 6a 65 63 74 20 63 61 6e 6e 6f 74 20 75 73 65 20 61 20 6e 75 6c 6c 20 49 56 } //1 : this object cannot use a null IV
		$a_03_2 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-80] 2e 00 6c 00 6f 00 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}