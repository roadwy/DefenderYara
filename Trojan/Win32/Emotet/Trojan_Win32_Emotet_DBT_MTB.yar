
rule Trojan_Win32_Emotet_DBT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18 40 89 44 24 ?? ff 4c 24 ?? 0f } //20
		$a_02_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 84 24 ?? ?? ?? ?? 8a 54 14 ?? 32 da 88 5d 00 } //20
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*20) >=20
 
}