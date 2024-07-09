
rule Trojan_Win32_Zusy_GCI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 b1 61 eb ?? 8d a4 24 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d bc 02 00 00 72 } //10
		$a_03_1 = {72 88 5c 24 ?? c6 44 24 ?? 61 c6 44 24 ?? 74 88 5c 24 ?? c6 44 24 ?? 74 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 68 c6 44 24 ?? 72 88 5c 24 ?? c6 44 24 ?? 61 c6 44 24 ?? 64 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}