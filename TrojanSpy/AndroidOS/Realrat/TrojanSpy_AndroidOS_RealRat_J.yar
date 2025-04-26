
rule TrojanSpy_AndroidOS_RealRat_J{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 73 65 6e 64 6c 61 72 67 65 73 6d 73 } //2 _sendlargesms
		$a_01_1 = {2f 70 61 6e 65 6c 73 65 74 74 69 6e 67 2f 75 72 6c 2e 74 78 74 } //2 /panelsetting/url.txt
		$a_01_2 = {74 79 70 65 3d 6e 65 77 6d 65 73 73 61 67 65 26 64 61 74 61 3d } //2 type=newmessage&data=
		$a_01_3 = {53 6e 61 6b 65 5f 70 68 6f 6e 65 6c 69 73 74 2e 74 78 74 } //2 Snake_phonelist.txt
		$a_01_4 = {5f 75 73 73 64 5f 6f 6e 72 65 63 65 69 76 65 75 73 73 64 72 65 73 70 6f 6e 73 65 } //2 _ussd_onreceiveussdresponse
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=6
 
}