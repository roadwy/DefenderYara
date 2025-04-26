
rule Trojan_AndroidOS_SAgnt_H_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 61 70 2e 61 70 70 2e 73 68 75 69 68 75 6c 75 2e 63 6f 6d 2f 47 61 6d 65 2f 47 61 6d 65 42 61 6e 6b } //1 wap.app.shuihulu.com/Game/GameBank
		$a_01_1 = {67 6f 2e 73 63 6c 74 31 30 30 31 30 2e 63 6f 6d 2f 63 6f 75 6e 74 2e 70 68 70 3f } //1 go.sclt10010.com/count.php?
		$a_01_2 = {67 65 74 53 69 6d 4f 70 65 72 61 74 6f 72 4e 61 6d 65 } //1 getSimOperatorName
		$a_01_3 = {64 65 6c 65 74 65 46 69 6c 65 } //1 deleteFile
		$a_01_4 = {73 6d 73 5f 72 65 63 65 69 76 65 64 } //1 sms_received
		$a_01_5 = {64 6f 77 6e 6c 6f 61 64 50 6c 75 67 } //1 downloadPlug
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}