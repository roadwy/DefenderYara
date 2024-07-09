
rule Trojan_Win32_Glupteba_EAN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {56 c4 08 00 88 ?? 8b e5 5d c2 04 } //10
		$a_00_1 = {c7 45 e8 20 37 ef c6 c7 45 d8 b9 79 37 9e 8b 4d 0c 8b 11 89 55 f8 8b 45 0c 8b 48 04 } //5
		$a_00_2 = {55 8b ec 8b 45 08 8b 08 2b 4d 0c 8b 55 08 89 0a 5d c2 08 00 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=10
 
}