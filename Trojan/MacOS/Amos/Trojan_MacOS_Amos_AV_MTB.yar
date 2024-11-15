
rule Trojan_MacOS_Amos_AV_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0b f6 c1 01 75 36 48 89 c8 48 d1 e8 41 bf 16 00 00 00 48 8b 5d c0 3c 16 74 5e 80 e1 fe 80 c1 02 } //1
		$a_01_1 = {0f b6 95 d8 fe ff ff 30 11 0f b6 95 d8 fe ff ff 30 51 01 30 51 02 0f b6 95 d8 fe ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1 75 d4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}