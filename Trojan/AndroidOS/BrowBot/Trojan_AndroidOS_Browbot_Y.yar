
rule Trojan_AndroidOS_Browbot_Y{
	meta:
		description = "Trojan:AndroidOS/Browbot.Y,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f ?? ?? 00 } //2
		$a_01_1 = {63 72 65 64 65 6e 74 69 61 6c 73 4c 61 75 6e 63 68 65 72 5f ?? ?? 00 } //2
		$a_01_2 = {64 61 74 61 5f ?? ?? 2f 69 6e 64 65 78 5f ?? ?? 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}