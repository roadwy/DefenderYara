
rule Trojan_Win32_Fareit_DZ_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {52 50 8b 45 e8 99 e8 ?? ?? ?? ?? 71 ?? e8 ?? ?? ?? ?? ?? 33 d2 8a 55 ef 33 94 85 ?? ?? ?? ?? 8b 45 f0 88 10 ff 45 f4 46 ff 4d e0 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}