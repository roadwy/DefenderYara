
rule Trojan_BAT_Lagos_MBEN_MTB{
	meta:
		description = "Trojan:BAT/Lagos.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 0a 06 02 7d 01 00 00 04 00 16 06 7b } //1
		$a_01_1 = {53 4b 53 4d 4b 57 43 4e 4a 77 42 71 4a } //1 SKSMKWCNJwBqJ
		$a_01_2 = {53 74 72 69 6e 67 54 6f 42 79 74 65 41 72 72 61 79 } //1 StringToByteArray
		$a_01_3 = {4f 55 6a 67 6f 54 } //1 OUjgoT
		$a_01_4 = {56 65 69 6c 2e 65 78 65 } //1 Veil.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}