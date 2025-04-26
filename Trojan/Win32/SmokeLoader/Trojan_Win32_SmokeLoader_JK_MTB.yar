
rule Trojan_Win32_SmokeLoader_JK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 03 45 ?? 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8 } //1
		$a_03_1 = {55 8b ec 8b 45 ?? 8b 4d ?? 31 08 5d c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}