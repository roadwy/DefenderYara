
rule Trojan_Win64_AVTamper_C{
	meta:
		description = "Trojan:Win64/AVTamper.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 65 72 6e 65 6c 62 61 73 65 2e 64 6c 6c 00 5c 5c 2e 5c 61 6d 73 64 6b 00 61 63 74 69 76 65 63 6f 6e 73 6f 6c 65 00 61 6e 74 69 20 6d 61 6c 77 61 72 65 } //1
		$a_01_1 = {63 73 66 61 6c 63 6f 6e 00 63 73 73 68 65 6c 6c 00 63 79 62 65 72 65 61 73 6f 6e 00 63 79 63 6c 6f 72 61 6d 61 00 63 79 6c 61 6e 63 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}