
rule TrojanSpy_AndroidOS_SmsThief_AH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 2f 6d 69 64 63 6c 65 61 6e 69 6e 67 2f 4d 79 52 65 63 69 65 76 65 72 } //1 com/app/midcleaning/MyReciever
		$a_01_1 = {6d 61 69 64 34 75 } //1 maid4u
		$a_03_2 = {3a 2f 2f 79 2d 90 02 05 2e 6f 6e 6c 69 6e 65 90 00 } //1
		$a_01_3 = {70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 } //1 pass=app168&cmd=sms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}