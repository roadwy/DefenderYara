
rule TrojanSpy_AndroidOS_Banker_C{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.C,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 4b 73 61 41 70 70 6c 69 63 61 74 69 6f 6e 3b } //3 /KsaApplication;
		$a_00_1 = {2f 4b 76 53 65 72 76 69 63 65 3b } //3 /KvService;
		$a_00_2 = {2f 56 63 41 63 74 69 76 69 74 79 3b } //3 /VcActivity;
		$a_00_3 = {2f 56 73 52 65 63 65 69 76 65 72 3b } //3 /VsReceiver;
		$a_00_4 = {61 73 63 32 56 30 51 32 39 74 63 47 39 75 } //2 asc2V0Q29tcG9u
		$a_00_5 = {5a 57 35 30 52 57 35 68 59 6d 78 6c 5a 46 4e 6c 64 48 52 70 62 6d 63 3d } //1 ZW50RW5hYmxlZFNldHRpbmc=
		$a_00_6 = {31 5a 47 46 73 64 6d 6c 72 4c 6e 4e 35 63 33 52 } //2 1ZGFsdmlrLnN5c3R
		$a_00_7 = {6c 62 53 35 45 5a 58 68 44 62 47 46 7a 63 30 78 76 59 57 52 6c 63 67 3d 3d } //1 lbS5EZXhDbGFzc0xvYWRlcg==
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1) >=15
 
}