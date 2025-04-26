
rule Trojan_BAT_CryptInject_UNK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.UNK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 02 00 00 01 20 00 00 00 00 20 46 7b 70 49 20 27 7b 70 49 61 9d fe 09 03 00 71 02 00 00 01 20 01 00 00 00 20 a6 f5 9f 5f 20 cb f5 9f 5f 61 9d fe 09 03 00 71 02 00 00 01 20 02 00 00 00 20 a2 3d 54 47 20 d1 3d 54 47 61 9d fe 09 03 00 71 02 00 00 01 20 03 00 00 00 20 18 ef 53 05 20 71 ef 53 05 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}