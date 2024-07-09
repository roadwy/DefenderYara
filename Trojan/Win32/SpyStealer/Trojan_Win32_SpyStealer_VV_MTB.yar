
rule Trojan_Win32_SpyStealer_VV_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 0f be 34 10 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb } //10
		$a_02_1 = {2e 00 00 00 c7 44 24 ?? 00 ?? 01 00 c7 44 24 ?? 20 30 4a 00 c7 04 24 fb ?? 4c 00 89 85 54 ff ff ff } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}