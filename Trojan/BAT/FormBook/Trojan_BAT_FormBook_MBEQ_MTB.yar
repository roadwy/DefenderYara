
rule Trojan_BAT_FormBook_MBEQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 5d 13 19 11 06 11 05 5d 13 1a 11 06 17 58 11 04 5d 13 1b 07 11 19 91 13 1c 20 00 01 00 00 13 1d 11 3f 20 90 01 04 5a 20 90 01 04 61 90 00 } //1
		$a_01_1 = {45 76 65 6e 74 5f 54 72 61 63 65 2e 44 61 6e 67 6e 68 61 70 2e 72 65 73 6f 75 72 63 65 } //1 Event_Trace.Dangnhap.resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}