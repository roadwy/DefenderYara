
rule Trojan_AndroidOS_FakeInst_S{
	meta:
		description = "Trojan:AndroidOS/FakeInst.S,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 61 6d 61 67 6f 6e 74 65 61 6d } //2 samagonteam
		$a_01_1 = {67 72 75 70 70 61 64 75 6e 61 } //2 gruppaduna
		$a_01_2 = {74 72 69 72 75 62 61 68 61 } //2 trirubaha
		$a_01_3 = {73 65 6e 64 53 4d 53 37 37 37 } //2 sendSMS777
		$a_01_4 = {67 65 74 6c 69 6e 6b 63 6f 6e 66 69 67 33 34 35 } //2 getlinkconfig345
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=4
 
}