
rule Trojan_Win32_Convagent_ART_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 41 0f b6 54 15 ?? 41 32 14 04 88 14 03 48 83 c0 ?? 48 39 c6 75 } //19
		$a_81_1 = {6c 69 62 63 75 72 6c 2e 64 6c 6c } //1 libcurl.dll
	condition:
		((#a_03_0  & 1)*19+(#a_81_1  & 1)*1) >=20
 
}