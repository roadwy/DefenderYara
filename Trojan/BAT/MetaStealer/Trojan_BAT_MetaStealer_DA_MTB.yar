
rule Trojan_BAT_MetaStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/MetaStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {01 57 bf a3 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 e3 00 00 00 fc 00 00 00 f3 01 } //3
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //3 SymmetricAlgorithm
		$a_01_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //3 System.Security.Cryptography
		$a_01_3 = {4d 75 6c 74 69 63 61 73 74 44 65 6c 65 67 61 74 65 } //3 MulticastDelegate
		$a_01_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //3 set_UseShellExecute
		$a_00_5 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 31 00 30 00 30 00 30 00 39 00 2d 00 31 00 31 00 31 00 31 00 31 00 7d 00 } //3 {11111-22222-10009-11111}
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_00_5  & 1)*3) >=18
 
}