
rule TrojanSpy_AndroidOS_Boxer_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Boxer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 65 73 74 41 64 64 43 6f 6e 74 61 63 74 } //1 testAddContact
		$a_00_1 = {73 65 63 72 65 74 2e 6a 61 62 6f 78 2e 72 75 } //1 secret.jabox.ru
		$a_00_2 = {4a 6f 6b 65 2d 42 4f 58 } //1 Joke-BOX
		$a_00_3 = {66 6c 69 72 74 2e } //1 flirt.
		$a_00_4 = {73 73 5f 6a 61 64 2e 70 68 70 } //1 ss_jad.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}