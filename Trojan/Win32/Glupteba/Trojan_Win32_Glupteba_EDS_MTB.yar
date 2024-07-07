
rule Trojan_Win32_Glupteba_EDS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {c7 45 e8 20 37 ef c6 c7 45 d8 b9 79 37 9e 8b 4d 0c 8b 11 89 55 f8 } //10
		$a_02_1 = {84 10 d6 cb c7 05 90 01 04 ff ff ff ff 8b 90 01 01 f4 c1 90 01 01 05 89 90 01 01 ec 8b 45 d4 01 45 ec 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}