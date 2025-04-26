
rule Trojan_MacOS_Amos_BW_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BW!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 3f c1 39 88 01 f8 37 e8 9f c1 39 08 02 f8 36 0d 00 00 14 e0 07 40 f9 ba 01 00 94 e8 df c0 39 08 ff ff 36 } //1
		$a_01_1 = {1c 1a 80 52 68 c3 00 51 1f 29 00 71 63 02 00 54 1d 00 00 14 c8 06 40 f9 3f 03 08 eb 42 0b 00 54 c8 02 40 f9 08 01 19 8b 1a 01 40 39 1b 05 40 39 48 c3 00 51 1f 29 00 71 43 fe ff 54 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}