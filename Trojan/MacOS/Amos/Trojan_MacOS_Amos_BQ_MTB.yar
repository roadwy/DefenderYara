
rule Trojan_MacOS_Amos_BQ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BQ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c9 5e c0 39 ca 02 40 f9 3f 01 00 71 49 b1 96 9a 29 69 68 38 ea 07 40 f9 4a 69 68 38 49 01 09 4a aa 5e c0 39 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 49 69 28 38 08 05 00 91 ff 02 08 eb } //1
		$a_01_1 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}