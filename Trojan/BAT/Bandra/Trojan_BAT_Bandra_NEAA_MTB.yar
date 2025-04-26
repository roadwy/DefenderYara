
rule Trojan_BAT_Bandra_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bandra.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 13 00 00 0a 8e 69 5d 91 06 08 91 61 d2 6f 14 00 00 0a 08 17 25 2c 17 58 16 } //10
		$a_01_1 = {58 75 72 74 74 6d 70 74 65 73 79 2e 65 78 65 } //5 Xurttmptesy.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}