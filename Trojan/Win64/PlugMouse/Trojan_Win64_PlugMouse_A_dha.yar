
rule Trojan_Win64_PlugMouse_A_dha{
	meta:
		description = "Trojan:Win64/PlugMouse.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 73 6f 73 61 6e 6f 2e 6a 70 67 } //3 //sosano.jpg
		$a_01_1 = {44 65 63 61 74 61 2e } //1 Decata.
		$a_01_2 = {49 6e 76 74 75 72 65 21 } //1 Invture!
		$a_01_3 = {67 68 73 64 66 73 64 66 67 68 68 75 21 } //1 ghsdfsdfghhu!
		$a_01_4 = {46 67 67 73 64 73 73 73 73 73 62 63 65 73 73 21 } //1 Fggsdsssssbcess!
		$a_01_5 = {69 6e 20 74 61 64 64 64 72 67 6c 65 64 21 } //1 in tadddrgled!
		$a_01_6 = {72 64 64 64 64 73 21 } //1 rdddds!
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}