
rule TrojanSpy_AndroidOS_Mbot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6e 73 74 61 6c 6c 2f 61 70 70 73 2f } //2 Linstall/apps/
		$a_01_1 = {2f 69 6e 6a 2e 7a 69 70 } //1 /inj.zip
		$a_01_2 = {2f 49 6e 6a 65 63 74 50 72 6f 63 3b } //1 /InjectProc;
		$a_01_3 = {2f 43 6f 6d 6d 61 6e 64 53 65 72 76 69 63 65 3b } //1 /CommandService;
		$a_01_4 = {2f 43 72 69 70 74 73 3b } //1 /Cripts;
		$a_01_5 = {2f 53 63 72 79 6e 6c 6f 63 6b 3b } //1 /Scrynlock;
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}