
rule Trojan_BAT_Disstl_AWQ_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {30 41 16 0b 2b 0c 06 07 9a 6f 90 01 03 0a 07 17 58 0b 07 06 8e 69 32 ee de 03 90 00 } //10
		$a_80_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 44 69 73 63 6f 72 64 } //\Microsoft\Windows\Start Menu\Programs\Discord  5
		$a_80_2 = {69 6e 64 65 78 2e 6a 73 } //index.js  4
		$a_80_3 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 } //discord_desktop_core  4
		$a_80_4 = {64 69 73 63 6f 72 64 5f 6d 6f 64 75 6c 65 73 } //discord_modules  4
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4) >=12
 
}