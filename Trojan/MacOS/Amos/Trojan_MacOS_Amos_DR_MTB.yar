
rule Trojan_MacOS_Amos_DR_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DR!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 05 00 11 6b 1d 40 92 ec 1f 40 f9 8d 69 6b 38 a9 01 09 0b 2e 1d 40 92 8f 69 6e 38 8f 69 2b 38 8d 69 2e 38 ec 1f 40 f9 8d 69 6b 38 8e 69 6e 38 cd 01 0d 0b ad 1d 40 92 8c 69 6d 38 ed 07 40 f9 ac 69 28 38 08 05 00 91 5f 01 08 eb } //1
		$a_01_1 = {ea 1f 40 f9 4b 69 69 38 ec 13 40 f9 8c 69 69 38 68 01 08 0b 08 01 0c 0b 0c 1d 40 92 4d 69 6c 38 4d 69 29 38 4b 69 2c 38 29 05 00 91 3f 01 04 f1 81 fe ff 54 ff 02 18 eb 40 03 00 54 08 00 80 d2 09 00 80 52 0b 00 80 d2 bf 06 00 f1 aa 86 9f 9a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}