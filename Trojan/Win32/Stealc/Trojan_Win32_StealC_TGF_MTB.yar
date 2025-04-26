
rule Trojan_Win32_StealC_TGF_MTB{
	meta:
		description = "Trojan:Win32/StealC.TGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e0 04 03 45 e4 8d 0c 1f 33 c1 33 45 ?? 89 45 ?? 8b 45 ec 29 45 ?? 81 c7 47 86 c8 61 83 6d f0 01 0f 85 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}