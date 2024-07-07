
rule TrojanSpy_BAT_Magento_A_bit{
	meta:
		description = "TrojanSpy:BAT/Magento.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 72 00 72 00 69 00 67 00 6f 00 68 00 65 00 73 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 64 00 6d 00 69 00 6e 00 6b 00 61 00 33 00 } //1 http://terrigohesh.com/adminka3
		$a_01_1 = {6e 00 65 00 77 00 5f 00 67 00 2e 00 70 00 68 00 70 00 3f 00 68 00 77 00 69 00 64 00 3d 00 } //1 new_g.php?hwid=
		$a_01_2 = {6d 00 61 00 67 00 65 00 6e 00 74 00 6f 00 } //1 magento
		$a_01_3 = {6f 00 70 00 65 00 6e 00 63 00 61 00 72 00 64 00 } //1 opencard
		$a_01_4 = {26 00 64 00 75 00 6d 00 6d 00 79 00 3d 00 26 00 6c 00 6f 00 67 00 69 00 6e 00 5b 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5d 00 3d 00 } //1 &dummy=&login[password]=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}