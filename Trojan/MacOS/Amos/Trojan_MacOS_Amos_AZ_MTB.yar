
rule Trojan_MacOS_Amos_AZ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AZ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 3f c1 39 68 00 f8 36 e0 1f 40 f9 41 00 00 94 e0 03 14 aa 3f 00 00 94 e0 03 13 aa 3d 00 00 94 e0 03 15 aa 2c 00 00 94 e0 07 40 f9 39 00 00 94 e8 df c0 39 68 fe ff 36 } //1
		$a_01_1 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb 01 fe ff 54 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}