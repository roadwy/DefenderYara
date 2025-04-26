
rule Trojan_BAT_NanoCoreRAT_A_MTB{
	meta:
		description = "Trojan:BAT/NanoCoreRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 a0 70 d0 fe 66 20 21 45 a1 f2 59 20 79 a6 33 e0 61 65 20 a4 ec bd ee 58 61 fe 09 00 00 61 d1 9d fe 0c 01 00 20 fd ff ff ff 66 65 66 59 25 fe 0e 01 00 20 6e 9e e3 19 66 20 89 be 04 0d 58 20 1a 20 21 f3 61 3c a5 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}