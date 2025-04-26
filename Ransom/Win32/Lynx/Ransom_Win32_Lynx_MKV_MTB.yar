
rule Ransom_Win32_Lynx_MKV_MTB{
	meta:
		description = "Ransom:Win32/Lynx.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe c2 88 94 31 b0 00 00 00 8b 54 24 10 33 c9 8b 74 24 20 8a 84 0c ?? ?? ?? ?? 41 30 04 37 47 8b 74 24 1c 3b fa 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}