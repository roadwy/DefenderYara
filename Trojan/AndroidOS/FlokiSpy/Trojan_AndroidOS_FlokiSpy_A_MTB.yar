
rule Trojan_AndroidOS_FlokiSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FlokiSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 61 63 6b 75 70 2e 73 70 79 6b 65 79 2d 66 6c 6f 6b 69 2e 6f 72 67 2f 61 64 64 2e 70 68 70 } //1 backup.spykey-floki.org/add.php
		$a_01_1 = {73 65 63 75 72 65 2f 6d 6f 76 69 6c 73 65 63 75 72 65 2f 63 6f 6d 2f 6d 6f 76 69 6c 73 65 63 75 72 65 } //1 secure/movilsecure/com/movilsecure
		$a_01_2 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_00_3 = {2f 4d 79 53 65 72 76 69 63 65 32 } //1 /MyService2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}