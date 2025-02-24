
rule Ransom_Win32_CylanceLoader_MKB_MTB{
	meta:
		description = "Ransom:Win32/CylanceLoader.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b fb 33 f6 8b 45 ?? 8d 0c 1e 8a 04 30 46 32 04 0f 88 01 3b f2 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}