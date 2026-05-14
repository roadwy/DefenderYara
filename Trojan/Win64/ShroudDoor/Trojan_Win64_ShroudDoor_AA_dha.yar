
rule Trojan_Win64_ShroudDoor_AA_dha{
	meta:
		description = "Trojan:Win64/ShroudDoor.AA!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 20 5b 5b 3a 67 72 61 70 68 3a 5d 5d 2b } //1 0 [[:graph:]]+
		$a_01_1 = {31 20 5b 5b 3a 67 72 61 70 68 3a 5d 5d 2b } //1 1 [[:graph:]]+
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 SELECT * FROM Win32_OperatingSystem
		$a_01_3 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 } //1 ROOT\CIMV2
		$a_01_4 = {11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}