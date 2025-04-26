
rule Trojan_AndroidOS_FinSpy_B{
	meta:
		description = "Trojan:AndroidOS/FinSpy.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 65 76 65 6e 74 62 61 73 65 64 2f 52 65 63 65 69 76 65 72 53 65 72 76 69 63 65 } //1 /eventbased/ReceiverService
		$a_00_1 = {4c 6f 72 67 2f 78 6d 6c 70 75 73 68 2f 76 33 2f 45 76 65 6e 74 42 61 73 65 64 53 65 72 76 69 63 65 } //1 Lorg/xmlpush/v3/EventBasedService
		$a_01_2 = {48 02 05 00 21 43 94 03 00 03 48 03 04 03 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}