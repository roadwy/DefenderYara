
rule Trojan_AndroidOS_MobSquze_B{
	meta:
		description = "Trojan:AndroidOS/MobSquze.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 65 73 53 74 6f 72 65 4d 65 73 73 61 67 65 } //2 doesStoreMessage
		$a_01_1 = {6e 6f 74 53 74 6f 72 69 6e 67 4d 65 73 73 61 67 65 } //2 notStoringMessage
		$a_01_2 = {6c 70 2e 6d 6f 62 73 71 75 65 65 7a 65 2e 63 6f 6d } //2 lp.mobsqueeze.com
		$a_01_3 = {53 51 55 45 45 5a 45 5f 52 45 51 55 45 53 54 } //2 SQUEEZE_REQUEST
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}