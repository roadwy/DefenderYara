
rule TrojanSpy_BAT_CenterPOS_A{
	meta:
		description = "TrojanSpy:BAT/CenterPOS.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4f 53 46 75 6c 6c 4e 61 6d 65 } //1 get_OSFullName
		$a_01_1 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 } //1 ServerComputer
		$a_01_2 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //1 GetRandomFileName
		$a_01_3 = {43 65 6e 74 65 72 50 6f 69 6e 74 2e 65 78 65 } //1 CenterPoint.exe
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}