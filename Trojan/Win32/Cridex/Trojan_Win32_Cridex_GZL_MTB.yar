
rule Trojan_Win32_Cridex_GZL_MTB{
	meta:
		description = "Trojan:Win32/Cridex.GZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 34 24 8a 07 32 c2 0f b6 4f ?? 32 ca e9 } //10
		$a_02_1 = {88 07 46 47 49 83 f9 ?? 0f 85 ?? ?? ?? ?? e9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8a 06 32 c2 e9 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}