
rule Trojan_MacOS_Amos_BU_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BU!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 8b 4d 2c 41 8d 04 19 83 f8 01 0f 86 ce 00 00 00 41 8b 45 24 8d 54 18 fe 48 89 d1 bf ff 7f 00 00 48 21 f9 41 0f b6 b4 0d c8 00 00 00 8d 4c 18 ff 48 21 f9 45 0f b6 94 0d c8 00 00 00 b9 02 01 00 00 29 d9 49 39 cf 49 0f 42 cf 4d 89 f8 } //1
		$a_03_1 = {4d 89 bd b8 00 00 00 31 c0 49 89 85 c0 00 00 00 45 89 8d a8 00 00 00 49 39 45 00 0f 94 c0 48 89 ce 4c 09 c6 0f 95 c3 30 c3 75 ?? 41 83 bd 84 00 00 00 00 75 ?? 41 8b 85 80 00 00 00 41 83 f9 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}