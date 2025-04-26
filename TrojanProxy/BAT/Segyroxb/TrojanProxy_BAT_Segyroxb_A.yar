
rule TrojanProxy_BAT_Segyroxb_A{
	meta:
		description = "TrojanProxy:BAT/Segyroxb.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 00 6f 00 66 00 66 00 69 00 63 00 69 00 61 00 6c 00 73 00 65 00 67 00 77 00 61 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 78 00 78 00 2e 00 64 00 61 00 74 00 } //8 /officialsegway.com/xx.dat
		$a_01_1 = {2f 00 61 00 64 00 76 00 65 00 6e 00 74 00 75 00 72 00 65 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 67 00 61 00 6d 00 65 00 73 00 2e 00 6f 00 72 00 67 00 2f 00 70 00 68 00 2f 00 6e 00 6f 00 74 00 69 00 66 00 79 00 2e 00 70 00 68 00 70 00 } //4 /adventureonlinegames.org/ph/notify.php
		$a_01_2 = {5c 55 73 65 72 73 5c 65 43 6f 4c 6f 47 79 5c 44 6f 63 75 6d 65 6e 74 73 } //2 \Users\eCoLoGy\Documents
		$a_01_3 = {50 72 6f 6a 65 63 74 73 5c 4d 79 50 68 5c 4d 79 50 68 5c 6f 62 6a 5c 44 65 62 75 67 5c 4d 79 50 68 2e 70 64 62 } //2 Projects\MyPh\MyPh\obj\Debug\MyPh.pdb
		$a_01_4 = {4b 69 6c 6c 00 43 6f 6e 74 72 6f 6c 00 53 79 73 74 65 6d 00 46 6f 72 6d 00 } //1
		$a_01_5 = {6d 61 74 61 72 6e 61 76 00 4d 79 50 68 2e 4d 79 } //1
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}