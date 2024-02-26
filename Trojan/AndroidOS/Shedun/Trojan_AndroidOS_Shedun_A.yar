
rule Trojan_AndroidOS_Shedun_A{
	meta:
		description = "Trojan:AndroidOS/Shedun.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 63 6f 64 65 44 65 78 41 6e 64 52 65 70 6c 61 63 65 } //01 00  decodeDexAndReplace
		$a_01_1 = {32 30 32 33 30 36 31 30 48 65 6c 6c 6f 44 6f 67 } //00 00  20230610HelloDog
	condition:
		any of ($a_*)
 
}