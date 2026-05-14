
rule Ransom_Win64_ClearWate_YBG_MTB{
	meta:
		description = "Ransom:Win64/ClearWate.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6c 65 61 72 57 61 74 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 ClearWater Ransomware
		$a_01_1 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 wmic shadowcopy delete
		$a_01_2 = {52 45 41 44 4d 45 2e 62 6d 70 } //1 README.bmp
		$a_01_3 = {64 65 63 72 79 70 74 69 6f 6e 20 6f 72 20 72 65 63 6f 76 65 72 79 } //1 decryption or recovery
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}