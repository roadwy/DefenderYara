
rule Trojan_Win32_Kryptik_GG_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 83 c0 01 89 45 f8 eb } //1
		$a_02_1 = {8b c0 8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 [0-08] 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}