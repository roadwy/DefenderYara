
rule Adware_MacOS_Cimpli_B_MTB{
	meta:
		description = "Adware:MacOS/Cimpli.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {79 0c a0 01 00 85 01 3f 00 00 00 ff ff 01 1f 00 4d 00 00 4d 05 ce 02 00 68 5b cc 02 00 f0 01 13 ca 02 00 93 02 0e ce 02 00 a1 02 43 00 00 00 ff ff 01 0c 00 36 00 00 36 12 54 00 48 22 00 00 ff ff 01 10 00 c9 03 00 00 c9 03 09 f2 03 00 d2 03 36 00 00 ff ff 01 0c 00 2a } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}