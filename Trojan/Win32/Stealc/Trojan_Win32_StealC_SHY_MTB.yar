
rule Trojan_Win32_StealC_SHY_MTB{
	meta:
		description = "Trojan:Win32/StealC.SHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 89 70 0c 89 50 08 89 08 c7 40 04 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 c6 8b 45 e8 8b 55 f4 89 d1 0f b6 54 10 02 31 f2 88 54 08 02 8b 45 f4 83 c0 01 89 45 f4 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}