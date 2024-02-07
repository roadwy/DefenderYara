
rule Trojan_AndroidOS_Netisend_A{
	meta:
		description = "Trojan:AndroidOS/Netisend.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6e 65 72 75 61 6e 2e 63 6f 6d 2f 6e 65 74 73 65 6e 64 2f 6e 6d 73 6d 2e 6a 73 70 3f 66 72 6f 6d 3d } //01 00  oneruan.com/netsend/nmsm.jsp?from=
		$a_01_1 = {65 72 65 67 69 5f 72 65 70 6c 61 63 65 } //01 00  eregi_replace
		$a_01_2 = {73 74 6f 70 53 65 6c 66 } //01 00  stopSelf
		$a_01_3 = {6f 6e 65 53 6f 66 74 44 62 } //00 00  oneSoftDb
	condition:
		any of ($a_*)
 
}