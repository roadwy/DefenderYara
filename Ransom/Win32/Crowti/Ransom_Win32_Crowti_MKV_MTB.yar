
rule Ransom_Win32_Crowti_MKV_MTB{
	meta:
		description = "Ransom:Win32/Crowti.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 08 0f b7 55 fe 52 e8 ?? ?? ?? ?? 83 c4 04 0f b7 c0 33 45 f8 25 ff 00 00 00 33 34 85 ?? ?? ?? ?? 89 75 f8 8b 4d f4 83 c1 02 89 4d f4 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}