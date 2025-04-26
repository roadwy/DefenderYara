
rule Trojan_BAT_Kryptik_ABDIND_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ABDIND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 39 30 63 38 39 36 31 66 2d 36 61 32 33 2d 34 66 30 35 2d 62 32 37 33 2d 33 35 66 35 30 66 37 35 35 34 64 37 } //10 $90c8961f-6a23-4f05-b273-35f50f7554d7
		$a_01_1 = {42 75 66 66 65 72 } //1 Buffer
		$a_01_2 = {43 6f 6e 76 6f } //1 Convo
		$a_01_3 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_4 = {57 6f 72 6b 65 72 32 } //1 Worker2
		$a_01_5 = {4a 6d 65 6b 65 6c 77 75 77 7a 75 64 79 79 77 73 69 62 6b 70 } //1 Jmekelwuwzudyywsibkp
		$a_01_6 = {57 6f 72 6b 65 72 31 } //1 Worker1
		$a_01_7 = {49 73 45 76 65 72 79 74 68 69 6e 67 44 6f 6e 65 } //1 IsEverythingDone
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}