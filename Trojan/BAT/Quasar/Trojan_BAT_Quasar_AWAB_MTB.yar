
rule Trojan_BAT_Quasar_AWAB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AWAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 02 00 fe 0c 04 00 fe 0c 01 00 fe 0c 04 00 91 20 aa 00 00 00 61 d2 9c } //4
		$a_01_1 = {fe 0c 01 00 fe 0c 04 00 8f 18 01 00 01 25 47 fe 0c 00 00 fe 0c 04 00 fe 0c 00 00 8e 69 5d 91 61 d2 52 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}