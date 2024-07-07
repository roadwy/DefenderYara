
rule TrojanSpy_AndroidOS_SmsTheif_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 53 6d 73 46 72 6f 6d 50 68 6f 6e 65 } //1 getSmsFromPhone
		$a_00_1 = {4c 63 68 69 6e 61 2f 67 6f 76 2f 73 76 6e 67 73 2f 53 6d 53 73 65 72 76 65 72 } //1 Lchina/gov/svngs/SmSserver
		$a_00_2 = {67 65 74 49 6e 66 6f } //1 getInfo
		$a_00_3 = {7a 6a 6a 73 6f 6e } //1 zjjson
		$a_00_4 = {70 63 64 75 66 61 76 76 62 7a 6b 62 7a 66 73 62 } //1 pcdufavvbzkbzfsb
		$a_00_5 = {72 65 63 65 69 76 65 54 69 6d 65 } //1 receiveTime
		$a_00_6 = {47 65 74 4e 65 74 49 70 } //1 GetNetIp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}