
rule Trojan_BAT_SpySnake_MI_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {b8 57 00 07 80 c3 22 02 28 09 00 00 0a 00 2a 3e 02 28 09 00 00 0a 00 02 03 7d 01 00 00 04 2a 22 02 28 } //01 00 
		$a_01_1 = {53 38 61 62 69 6c 69 38 79 } //01 00  S8abili8y
		$a_01_2 = {67 65 74 5f 47 65 74 50 61 74 63 68 } //01 00  get_GetPatch
		$a_01_3 = {52 35 63 6f 6d 6d 35 6e 64 } //01 00  R5comm5nd
		$a_01_4 = {58 00 6f 00 78 00 6f 00 54 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  XoxoTor.exe
	condition:
		any of ($a_*)
 
}