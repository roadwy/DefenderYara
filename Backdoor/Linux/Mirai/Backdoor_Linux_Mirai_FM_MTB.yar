
rule Backdoor_Linux_Mirai_FM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c2 1a 08 00 c2 24 08 00 c2 10 02 00 1f 00 63 30 1f 00 84 30 c2 2e 08 00 21 10 c2 01 21 18 c3 01 21 28 c5 01 21 20 c4 01 00 00 46 ?? 00 00 67 ?? 00 00 82 ?? 00 00 a3 ?? fc ff 6b 25 00 00 46 a1 01 00 47 a1 02 00 42 a1 03 00 43 a1 21 28 80 01 19 ?? ?? ?? 04 00 4a 25 } //1
		$a_03_1 = {c0 1a 06 00 c2 2c 07 00 26 18 c3 00 26 28 e5 00 26 28 65 00 04 00 02 29 02 1a 03 00 21 20 60 00 ef ?? ?? ?? 26 18 65 00 0b ?? ?? ?? 26 18 85 00 00 00 43 a5 fe ff 08 25 ec ?? ?? ?? 02 00 4a 25 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}