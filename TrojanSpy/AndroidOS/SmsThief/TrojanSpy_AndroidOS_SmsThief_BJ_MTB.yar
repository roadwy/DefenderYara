
rule TrojanSpy_AndroidOS_SmsThief_BJ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 63 73 74 73 70 72 74 61 70 70 68 64 6e 2e 61 6d 73 73 6d 6d 73 73 } //1 com.cstsprtapphdn.amssmmss
		$a_01_1 = {6d 73 73 2e 74 65 63 68 73 68 6f 77 2e 63 6c 6f 75 64 2f 73 62 69 61 70 70 } //1 mss.techshow.cloud/sbiapp
		$a_01_2 = {2f 61 64 6d 69 6e 64 61 74 61 2e 74 78 74 } //1 /admindata.txt
		$a_01_3 = {52 65 63 65 69 76 65 53 6d 73 } //1 ReceiveSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}