
rule Trojan_AndroidOS_SMSer_C{
	meta:
		description = "Trojan:AndroidOS/SMSer.C,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 72 69 6e 74 54 69 6d 65 73 00 2b 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 54 49 4d 45 53 3d } //1 牰湩呴浩獥⬀㴽㴽㴽㴽㴽㴽㴽㴽㴽䥔䕍㵓
		$a_01_1 = {62 6c 6f 63 6b 5f 6e 75 6d 62 65 72 73 } //5 block_numbers
		$a_01_2 = {61 63 74 76 69 74 79 43 6c 61 73 73 00 } //2
		$a_01_3 = {6e 65 74 2f 55 52 4c 43 6f 6e 6e 65 63 74 69 6f 6e 3b } //5 net/URLConnection;
		$a_01_4 = {67 65 74 49 6d 65 69 00 } //2 敧䥴敭i
		$a_01_5 = {67 65 74 50 68 6f 6e 65 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=15
 
}