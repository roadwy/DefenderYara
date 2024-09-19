
rule Trojan_AndroidOS_Badpack_ET{
	meta:
		description = "Trojan:AndroidOS/Badpack.ET,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 37 66 31 61 66 63 37 34 36 34 33 36 66 30 38 } //1 17f1afc746436f08
		$a_01_1 = {4c 71 75 30 64 61 36 2f 64 33 78 30 2f 69 74 30 70 6d 78 3b } //1 Lqu0da6/d3x0/it0pmx;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}