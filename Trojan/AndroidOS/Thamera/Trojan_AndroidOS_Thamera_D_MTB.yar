
rule Trojan_AndroidOS_Thamera_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 65 72 6d 69 73 73 69 6f 6e 41 6b 73 43 6f 75 6e 74 65 72 } //1 permissionAksCounter
		$a_01_1 = {6f 72 67 2e 6a 61 63 6b 61 6a 6b 73 2e 74 68 65 72 6d 69 73 68 } //1 org.jackajks.thermish
		$a_01_2 = {73 65 6e 64 4e 65 77 53 4d 53 } //1 sendNewSMS
		$a_01_3 = {46 69 72 65 42 61 73 65 6d 65 6f 71 61 6c 65 68 65 75 } //1 FireBasemeoqaleheu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}