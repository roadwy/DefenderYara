
rule Ransom_Win32_Trigona_MKV_MTB{
	meta:
		description = "Ransom:Win32/Trigona.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 8b 38 ff 97 88 00 00 00 8b 45 f8 0f b6 00 32 45 e4 88 06 8d 53 60 8d 43 61 b9 0f 00 00 00 e8 74 d1 f2 ff 0f b6 06 88 43 6f ff 45 90 01 01 46 ff 4d f4 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}