
rule Trojan_AndroidOS_Banker_U_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 62 70 6d 2e 62 61 6e 6b 65 72 } //1 com.bpm.banker
		$a_01_1 = {63 6f 6d 2f 67 6f 6f 67 6c 65 2f 73 6d 73 72 65 61 64 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/google/smsreader/MainActivity
		$a_01_2 = {73 6d 73 46 69 73 68 2f 73 65 6e 64 44 61 74 61 2e 70 68 70 } //1 smsFish/sendData.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}