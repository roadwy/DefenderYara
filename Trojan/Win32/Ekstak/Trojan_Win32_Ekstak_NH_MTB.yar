
rule Trojan_Win32_Ekstak_NH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 33 01 55 68 ?? ?? ?? ?? 01 ff 30 64 89 ?? 3b 01 7e } //10
		$a_03_1 = {0f b6 d3 88 01 17 b9 ?? ?? ?? ?? 01 c6 33 d2 f7 f1 89 01 4b 85 f6 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}