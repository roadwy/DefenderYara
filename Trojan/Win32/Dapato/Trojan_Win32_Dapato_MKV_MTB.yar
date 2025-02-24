
rule Trojan_Win32_Dapato_MKV_MTB{
	meta:
		description = "Trojan:Win32/Dapato.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 80 40 57 46 00 8a 92 40 57 46 00 c0 f8 04 c0 e2 02 24 03 32 c2 8b d7 88 04 13 8b 55 ?? 43 83 fa 10 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}