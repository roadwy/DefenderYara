
rule Ransom_Win32_Acepy_MKV_MTB{
	meta:
		description = "Ransom:Win32/Acepy.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 89 45 e4 8b 45 f0 8b 4d e4 31 d2 f7 f1 8b 45 0c 01 d0 8b 4d e8 0f be 09 0f be 10 31 d1 8b 45 ?? 88 08 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}