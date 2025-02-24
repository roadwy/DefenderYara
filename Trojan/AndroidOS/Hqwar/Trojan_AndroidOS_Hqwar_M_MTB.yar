
rule Trojan_AndroidOS_Hqwar_M_MTB{
	meta:
		description = "Trojan:AndroidOS/Hqwar.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 09 02 05 d0 7a d7 dd dc 0b 05 02 48 0b 01 0b 14 0c a5 6f 0a 00 91 0d 0a 07 b1 cd 92 0c 0a 07 b0 cd da 0d 0d 00 b0 9d b3 aa b3 8a df 09 0a 01 b0 9d 94 09 07 07 b0 9d 97 09 0d 0b 8d 99 4f 09 04 05 13 09 26 05 b3 79 d8 05 05 01 } //1
		$a_03_1 = {13 09 27 00 35 98 ?? ?? d3 59 85 22 d0 99 f6 de 93 07 03 07 91 07 09 07 d8 08 08 01 28 f2 36 35 ?? ?? d8 08 05 30 d8 08 08 1a b0 78 b0 83 12 18 33 37 ?? ?? ?? 09 08 03 b0 79 91 05 09 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}