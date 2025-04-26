
rule Trojan_Win64_ZamTamper_C{
	meta:
		description = "Trojan:Win64/ZamTamper.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 4c 44 20 50 44 42 2e 01 00 00 00 44 3a 5c 44 65 76 5c 30 35 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 78 36 34 5c 52 65 6c ?? 61 73 65 5c 30 35 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}