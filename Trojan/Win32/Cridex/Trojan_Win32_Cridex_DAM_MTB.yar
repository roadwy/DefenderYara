
rule Trojan_Win32_Cridex_DAM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 38 ae 08 00 b8 38 ae 08 00 a1 ?? ?? ?? ?? eb 00 8b f8 33 f9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 3d 90 1b 01 a1 ?? ?? ?? ?? 8b 0d 90 1b 01 89 08 } //1
		$a_81_1 = {33 35 32 34 35 32 33 34 35 38 69 32 33 34 39 38 35 75 32 38 33 34 35 32 68 38 33 34 68 35 38 32 79 34 33 68 35 38 32 68 33 34 39 35 } //1 3524523458i234985u283452h834h582y43h582h3495
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}