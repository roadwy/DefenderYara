
rule Trojan_Win64_IcedID_AU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 54 4e 6b 71 35 75 52 79 48 48 54 41 50 45 48 47 77 34 32 6a 51 6a 4e } //1 BTNkq5uRyHHTAPEHGw42jQjN
		$a_01_1 = {42 5a 75 77 47 44 79 51 6e 46 35 57 6d 78 79 5a 30 } //1 BZuwGDyQnF5WmxyZ0
		$a_01_2 = {47 58 78 6d 42 75 74 66 68 5a 66 6b 5a 41 77 67 56 48 4e 4e 45 47 } //1 GXxmButfhZfkZAwgVHNNEG
		$a_01_3 = {47 66 62 5a 4e 6b 42 45 6c 57 50 45 32 70 31 5a 58 4c 4e 55 43 31 79 37 39 76 68 50 } //1 GfbZNkBElWPE2p1ZXLNUC1y79vhP
		$a_01_4 = {49 6e 33 56 51 47 49 6a 4c 78 76 52 36 67 75 34 4e 4c 64 48 59 76 4b 67 4c 64 48 38 53 } //1 In3VQGIjLxvR6gu4NLdHYvKgLdH8S
		$a_01_5 = {4b 76 6e 66 49 32 4f 68 44 63 48 44 5a 42 44 4b 38 38 73 46 36 6e 32 39 6d 6b } //1 KvnfI2OhDcHDZBDK88sF6n29mk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}