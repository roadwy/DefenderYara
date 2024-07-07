
rule Trojan_AndroidOS_Iop_A_xp{
	meta:
		description = "Trojan:AndroidOS/Iop.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 52 61 6e 64 6f 6d 69 50 4b 63 } //1 getRandomiPKc
		$a_00_1 = {65 6d 6f 76 65 00 6f 70 65 6e 00 77 72 69 74 65 00 63 6c 6f 73 65 00 4a 4e } //1
		$a_00_2 = {00 5f 5a 31 34 5f 5f 67 6e 75 5f 55 6e 77 69 6e } //1 开ㅚ弴束畮啟睮湩
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}