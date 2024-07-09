
rule VirTool_BAT_CryptInject_CD_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 9a 0c 08 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 2c 21 } //1
		$a_03_1 = {08 14 17 8d 01 00 00 01 13 06 11 06 16 02 a2 11 06 6f ?? 00 00 0a 74 ?? 00 00 01 0d de 13 26 de 00 } //1
		$a_01_2 = {91 61 d2 9c } //1
		$a_01_3 = {47 00 65 00 74 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6e 00 67 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 GetExecutingAssembly
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}