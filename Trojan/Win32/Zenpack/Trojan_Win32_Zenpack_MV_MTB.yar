
rule Trojan_Win32_Zenpack_MV_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 14 38 40 3b c1 72 ?? 90 18 a1 [0-04] 8b 0d [0-04] c1 e8 ?? 85 c0 76 13 56 57 8b f9 8b f0 e8 [0-04] 83 c7 08 4e 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}