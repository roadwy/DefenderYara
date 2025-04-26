
rule Trojan_Win32_Kryptik_GN_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 83 c0 01 89 45 f8 eb } //1
		$a_02_1 = {8b c0 8b ca 8b c0 [0-0d] 33 [0-0e] c7 05 [0-08] 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 [0-01] 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}