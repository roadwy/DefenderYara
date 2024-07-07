
rule Trojan_BAT_NjRat_NEBY_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 93 00 00 0a 02 11 54 28 94 00 00 0a 20 14 38 01 00 28 4d 00 00 06 18 18 6f 3e 00 00 06 6f 95 00 00 0a 0c 08 14 } //10
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //5 RPF:SmartAssembly
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}