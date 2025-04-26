
rule Trojan_AndroidOS_Banjeon_A{
	meta:
		description = "Trojan:AndroidOS/Banjeon.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 74 68 69 73 61 70 70 2f 63 6f 6e 6e 65 63 74 69 6f 6e 2f 43 6f 6e 6e 65 63 74 69 6f 6e 52 65 73 75 6c 74 42 65 61 6e } //2 mythisapp/connection/ConnectionResultBean
		$a_01_1 = {6d 79 74 68 69 73 61 70 70 2f 74 61 73 6b 2f 4c 6f 6e 67 43 6f 6e 6e 65 63 74 69 6f 6e 45 6e 67 69 6e 65 } //2 mythisapp/task/LongConnectionEngine
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}