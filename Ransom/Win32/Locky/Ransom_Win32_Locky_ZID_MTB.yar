
rule Ransom_Win32_Locky_ZID_MTB{
	meta:
		description = "Ransom:Win32/Locky.ZID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 e8 d2 eb 24 01 80 e3 01 02 d8 0f b6 c3 0d 32 c1 2c 65 03 d0 8a 45 ff 80 e3 01 02 c0 0f b6 f3 02 c3 88 45 ff 8b ce 83 c9 19 8b c6 83 f0 2e 03 d1 03 d0 83 7d f8 00 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}