
rule Trojan_BAT_SpySnake_MI_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 57 00 07 80 c3 22 02 28 09 00 00 0a 00 2a 3e 02 28 09 00 00 0a 00 02 03 7d 01 00 00 04 2a 22 02 28 } //5
		$a_01_1 = {53 38 61 62 69 6c 69 38 79 } //1 S8abili8y
		$a_01_2 = {67 65 74 5f 47 65 74 50 61 74 63 68 } //1 get_GetPatch
		$a_01_3 = {52 35 63 6f 6d 6d 35 6e 64 } //1 R5comm5nd
		$a_01_4 = {58 00 6f 00 78 00 6f 00 54 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 XoxoTor.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule Trojan_BAT_SpySnake_MI_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 10 07 08 9a 6f ?? ?? ?? 0a 06 17 58 0a 08 17 58 0c 08 07 8e 69 32 ea } //5
		$a_01_1 = {64 37 31 38 65 39 31 31 2d 65 31 65 34 2d 34 38 38 31 2d 39 33 61 34 2d 61 61 63 37 32 30 65 39 61 37 63 62 } //5 d718e911-e1e4-4881-93a4-aac720e9a7cb
		$a_01_2 = {78 73 68 77 2e 50 72 6f 70 65 72 74 69 65 73 } //5 xshw.Properties
		$a_01_3 = {73 65 6c 66 44 65 6c 65 74 65 } //1 selfDelete
		$a_01_4 = {77 65 62 68 6f 6f 6b } //1 webhook
		$a_01_5 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 KillProcess
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=18
 
}