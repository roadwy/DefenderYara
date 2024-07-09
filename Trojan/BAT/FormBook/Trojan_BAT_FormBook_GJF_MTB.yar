
rule Trojan_BAT_FormBook_GJF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 17 00 00 0f 00 28 ?? ?? ?? 0a 0b 07 06 58 03 06 91 52 00 00 06 17 58 0a 06 03 8e 69 fe 04 0c 08 2d df } //10
		$a_80_1 = {31 32 48 4c 46 59 57 77 77 32 68 35 73 74 39 79 61 54 4d 79 6c 67 } //12HLFYWww2h5st9yaTMylg  1
		$a_80_2 = {4f 48 54 62 63 77 58 34 4b 30 42 5a 52 4e 44 71 } //OHTbcwX4K0BZRNDq  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}