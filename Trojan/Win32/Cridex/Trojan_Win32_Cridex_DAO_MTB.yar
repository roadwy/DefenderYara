
rule Trojan_Win32_Cridex_DAO_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 38 ae 08 00 b8 38 ae 08 00 a1 ?? ?? ?? ?? eb 00 8b d8 33 d9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d 90 1b 01 a1 ?? ?? ?? ?? 8b 0d 90 1b 01 89 08 } //1
		$a_81_1 = {35 36 39 67 75 35 6d 39 75 79 68 33 39 75 38 35 68 79 38 74 75 33 68 34 35 38 39 75 74 68 33 39 34 35 38 75 39 68 33 38 39 75 34 } //1 569gu5m9uyh39u85hy8tu3h4589uth39458u9h389u4
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}