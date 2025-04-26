
rule Ransom_Win32_Cicada_MKV_MTB{
	meta:
		description = "Ransom:Win32/Cicada.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c7 08 39 f9 75 ?? 85 d2 74 ?? 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 0f b6 94 0c d8 00 00 00 30 14 08 41 39 cb 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}