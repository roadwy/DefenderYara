
rule TrojanSpy_AndroidOS_SmsThief_BN_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BN!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 6d 73 72 65 61 65 } //1 com/example/smsreae
		$a_03_1 = {0a 00 0c 0a 1a 00 ?? 80 71 20 83 08 0a 00 0c 0a 5b 9a c7 4b 6e 10 e7 02 0b 00 0c 0a 1a 00 ?? 7f 6e 20 12 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}