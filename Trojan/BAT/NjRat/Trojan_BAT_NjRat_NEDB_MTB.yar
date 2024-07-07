
rule Trojan_BAT_NjRat_NEDB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 02 16 fe 01 13 08 11 08 3a c5 ff ff ff 28 52 00 00 0a 09 28 53 00 00 0a 6f 54 00 00 0a 13 06 11 06 14 } //10
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 RPF:SmartAssembly
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}