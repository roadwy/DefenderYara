
rule Trojan_AndroidOS_InfoStealer_O_MTB{
	meta:
		description = "Trojan:AndroidOS/InfoStealer.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 54 68 69 72 64 41 70 70 4c 69 73 74 } //1 getThirdAppList
		$a_00_1 = {6c 69 76 65 43 61 6c 6c 48 69 73 74 6f 72 79 } //1 liveCallHistory
		$a_00_2 = {73 74 61 72 74 53 74 72 65 61 6d 69 6e 67 } //1 startStreaming
		$a_00_3 = {64 65 6c 65 74 65 54 68 69 72 64 41 70 70 } //1 deleteThirdApp
		$a_00_4 = {73 74 61 72 74 4c 69 76 65 52 65 63 6f 72 64 } //1 startLiveRecord
		$a_00_5 = {73 6d 73 4c 69 73 74 } //1 smsList
		$a_00_6 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 3d } //1 &default_dialer_package_name=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}