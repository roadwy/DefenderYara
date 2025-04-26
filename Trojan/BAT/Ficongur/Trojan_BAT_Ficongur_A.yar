
rule Trojan_BAT_Ficongur_A{
	meta:
		description = "Trojan:BAT/Ficongur.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 57 4f 52 4b 5c 65 6e 63 72 79 70 74 65 72 } //8 _WORK\encrypter
		$a_01_1 = {48 69 64 64 65 6e 54 65 61 72 5c } //4 HiddenTear\
		$a_01_2 = {68 69 64 64 65 6e 2d 74 65 61 72 2d 6d 61 73 74 65 72 } //4 hidden-tear-master
		$a_01_3 = {4d 79 65 78 70 65 72 65 6d 65 6e 74 73 } //2 Myexperements
		$a_01_4 = {5c 77 69 6e 75 70 64 61 74 65 5c 77 } //2 \winupdate\w
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=14
 
}