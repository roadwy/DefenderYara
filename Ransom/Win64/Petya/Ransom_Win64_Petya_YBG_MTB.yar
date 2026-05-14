
rule Ransom_Win64_Petya_YBG_MTB{
	meta:
		description = "Ransom:Win64/Petya.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 65 74 79 61 20 4d 42 52 20 65 6e 63 72 79 70 74 69 6f 6e } //1 Petya MBR encryption
		$a_01_1 = {64 65 6c 65 74 69 6e 67 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 deleting encrypted files
		$a_01_2 = {52 45 41 44 4d 45 } //1 README
		$a_01_3 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 20 4d 42 52 } //1 encrypted MBR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}