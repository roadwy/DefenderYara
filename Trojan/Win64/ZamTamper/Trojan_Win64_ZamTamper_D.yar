
rule Trojan_Win64_ZamTamper_D{
	meta:
		description = "Trojan:Win64/ZamTamper.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7a 61 2e 73 79 73 53 74 72 69 6e 67 46 6f 72 6d 61 74 5b 5d 62 79 74 65 73 74 72 69 6e 67 33 39 30 36 32 35 68 61 6e 67 75 70 6b 69 6c 6c 65 64 6c 69 73 ?? 65 6e 73 6f 63 6b 65 74 47 65 74 41 63 65 47 65 74 41 43 50 73 65 6e 64 74 6f 75 69 6e 74 31 36 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}