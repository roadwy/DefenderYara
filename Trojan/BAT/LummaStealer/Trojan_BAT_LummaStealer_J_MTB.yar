
rule Trojan_BAT_LummaStealer_J_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 fd 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 93 09 00 00 79 03 } //4
		$a_01_1 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //2 GetDelegateForFunctionPointer
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}