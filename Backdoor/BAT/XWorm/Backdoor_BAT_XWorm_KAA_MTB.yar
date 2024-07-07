
rule Backdoor_BAT_XWorm_KAA_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 e3 81 9f 4c 6e 4a 6c 62 47 39 6a e3 81 9f e3 81 9f e3 81 9f 4d e3 81 9f e3 81 9f e3 81 9f e3 81 9f e3 } //1
		$a_01_1 = {67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a e3 81 9f e3 } //1
		$a_01_2 = {53 68 75 74 64 6f 77 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 ShutdownEventHandler
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}