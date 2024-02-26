
rule Trojan_AndroidOS_EvilInst_B_MTB{
	meta:
		description = "Trojan:AndroidOS/EvilInst.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 72 74 69 6e 52 65 63 65 69 76 65 72 } //01 00  ConfirtinReceiver
		$a_01_1 = {46 4c 41 47 5f 43 4f 4e 46 49 52 4d 5f 4b 57 31 } //01 00  FLAG_CONFIRM_KW1
		$a_01_2 = {4e 68 61 6e 52 65 63 65 69 76 65 72 } //01 00  NhanReceiver
		$a_01_3 = {61 70 69 63 68 65 63 6b 73 75 62 73 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d } //00 00  apichecksubs.modobomco.com
	condition:
		any of ($a_*)
 
}