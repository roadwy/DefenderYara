
rule Ransom_Win32_Onion_GID_MTB{
	meta:
		description = "Ransom:Win32/Onion.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 50 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 2e c6 45 ?? 5c 88 5d fe ff d7 } //10
		$a_03_1 = {71 00 66 c7 45 ?? 3f 00 66 c7 45 ?? 0c 00 66 89 4d ?? 66 c7 45 ?? 0c 00 66 c7 45 ?? fb 00 66 c7 45 ?? 37 00 66 c7 45 ?? 60 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}