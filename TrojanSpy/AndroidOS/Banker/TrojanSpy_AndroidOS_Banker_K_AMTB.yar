
rule TrojanSpy_AndroidOS_Banker_K_AMTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.K!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 61 73 66 2f 64 73 66 61 65 65 } //6 com/asf/dsfaee
		$a_00_1 = {63 6f 6d 2f 61 73 64 66 65 65 2f 6c 6f 6b 69 6b } //6 com/asdfee/lokik
		$a_00_2 = {53 69 6d 53 6c 6f 74 30 } //2 SimSlot0
		$a_00_3 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 76 61 6c 69 64 20 61 74 6d } //1 Please enter valid atm
		$a_00_4 = {43 30 38 32 36 61 34 30 } //2 C0826a40
		$a_00_5 = {72 65 63 65 69 76 65 53 6d 73 } //1 receiveSms
	condition:
		((#a_00_0  & 1)*6+(#a_00_1  & 1)*6+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1) >=9
 
}