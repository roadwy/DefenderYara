
rule Trojan_BAT_NjRat_S_MTB{
	meta:
		description = "Trojan:BAT/NjRat.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 1d 0f 00 1a 28 90 09 05 00 (6f|28) ?? ?? 00 [0a 06 2b] ?? ?? ?? ?? ?? ?? ?? ?? 00 06 26 } //1
		$a_01_1 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00 } //1
		$a_01_2 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}