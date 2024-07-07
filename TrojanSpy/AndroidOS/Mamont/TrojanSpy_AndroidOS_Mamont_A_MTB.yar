
rule TrojanSpy_AndroidOS_Mamont_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mamont.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 61 69 6b 6f 2e 72 65 6e 74 } //5 com.saiko.rent
		$a_01_1 = {75 61 2e 77 61 72 64 65 6e 2e 6f 6e 6c 79 66 61 6e 73 } //5 ua.warden.onlyfans
		$a_01_2 = {72 65 61 64 4c 61 73 74 31 30 4d 65 73 73 61 67 65 73 } //1 readLast10Messages
		$a_01_3 = {2f 63 6f 64 65 69 6e 70 75 74 2e 70 68 70 } //1 /codeinput.php
		$a_01_4 = {73 65 6e 64 4e 6f 74 69 66 79 } //1 sendNotify
		$a_01_5 = {72 65 6d 6f 74 65 4d 65 73 73 61 67 65 } //1 remoteMessage
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}