
rule Trojan_MacOS_SAgnt_E_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 00 80 d2 a9 f4 85 d2 29 30 b1 f2 e9 a7 df f2 a9 3d e9 f2 ea 03 00 aa 0b 09 7d 92 2b 25 cb 9a 4c 01 40 39 8b 01 0b 4a 4b 15 00 38 08 21 00 91 1f a1 01 f1 21 ff ff 54 1f 34 00 39 e8 03 00 91 } //1
		$a_01_1 = {a8 02 40 f9 e0 03 15 aa 00 01 3f d6 08 08 40 39 28 01 00 34 08 00 40 39 a9 09 80 52 08 01 09 4a 08 00 00 39 08 04 40 39 08 79 19 52 08 04 00 39 1f 08 00 39 a8 83 03 d1 08 05 00 d1 09 1d 40 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}