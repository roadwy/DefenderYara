
rule Trojan_AndroidOS_Basbanke_N{
	meta:
		description = "Trojan:AndroidOS/Basbanke.N,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 61 63 74 69 6f 6e 3d 57 68 61 74 73 43 68 65 63 6b 65 72 26 6f 70 65 72 61 74 6f 72 } //2 &action=WhatsChecker&operator
		$a_01_1 = {26 61 63 74 69 6f 6e 3d 6c 61 73 74 4f 54 50 26 6f 70 65 72 61 74 6f 72 3d } //2 &action=lastOTP&operator=
		$a_01_2 = {26 61 63 74 69 6f 6e 3d 62 61 6c 61 6e 63 65 26 6f 70 65 72 61 74 6f 72 3d } //2 &action=balance&operator=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}