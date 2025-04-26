
rule Trojan_AndroidOS_Pootel_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Pootel.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 63 68 65 63 6b 73 75 62 73 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d } //1 apichecksubs.modobomco.com
		$a_00_1 = {63 6f 6d 2f 63 68 65 63 6b 2d 73 75 62 73 3f 63 6f 75 6e 74 72 79 } //1 com/check-subs?country
		$a_00_2 = {43 6f 6e 66 69 72 6d 53 6d 73 52 65 63 65 69 76 65 72 } //1 ConfirmSmsReceiver
		$a_01_3 = {53 49 4d 4f 50 45 52 41 } //1 SIMOPERA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}