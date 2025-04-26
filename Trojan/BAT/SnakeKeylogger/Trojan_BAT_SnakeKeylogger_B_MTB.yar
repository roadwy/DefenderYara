
rule Trojan_BAT_SnakeKeylogger_B_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d b2 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 65 01 00 0a 1f 10 28 66 01 00 0a } //2
		$a_01_1 = {61 34 63 39 39 35 34 63 2d 39 37 64 39 2d 34 66 31 37 2d 61 32 32 36 2d 31 35 65 61 38 64 64 64 39 33 33 31 } //1 a4c9954c-97d9-4f17-a226-15ea8ddd9331
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_SnakeKeylogger_B_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 69 70 70 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Lipps.Resources.resources
		$a_01_1 = {30 00 30 00 27 00 30 00 30 00 27 00 } //2 00'00'
		$a_01_2 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 } //2 Control_Run
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_4 = {3c 00 39 00 33 00 3c 00 43 00 32 00 3c 00 30 00 30 00 23 00 3c 00 43 00 30 00 23 00 3c 00 30 00 44 00 } //2 <93<C2<00#<C0#<0D
		$a_01_5 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=10
 
}