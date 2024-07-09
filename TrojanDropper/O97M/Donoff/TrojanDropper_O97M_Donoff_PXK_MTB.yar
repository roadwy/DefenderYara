
rule TrojanDropper_O97M_Donoff_PXK_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.PXK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {5c 63 61 6c 63 2e 65 78 65 90 0a 32 00 74 65 73 74 31 3d 73 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 } //1
		$a_02_1 = {5c 6d 73 70 61 69 6e 74 2e 65 78 65 90 0a 32 00 3d 73 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 } //1
		$a_00_2 = {3d 65 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 26 22 5c 64 65 73 6b 74 6f 70 22 26 22 5c 69 61 6d 68 65 72 65 2e 74 78 74 } //1 =environ("userprofile")&"\desktop"&"\iamhere.txt
		$a_00_3 = {69 61 6d 77 61 74 63 68 69 6e 67 79 6f 75 2e 2e 2e 61 6e 79 74 69 6d 65 2c 61 6e 79 77 68 65 72 65 } //1 iamwatchingyou...anytime,anywhere
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}