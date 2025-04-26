
rule Trojan_Win32_Convagent_AU_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 04 58 8b 54 24 54 01 c2 31 ca 88 54 04 58 83 c0 01 83 f8 ?? 75 e7 } //1
		$a_03_1 = {89 f8 88 44 24 ?? 83 c6 02 83 f6 ?? 89 f0 88 44 24 ?? 83 c3 03 83 f3 ?? 88 5c 24 ?? 83 c1 04 83 f1 ?? 88 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}