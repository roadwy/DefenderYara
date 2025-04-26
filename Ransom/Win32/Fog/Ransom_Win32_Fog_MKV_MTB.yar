
rule Ransom_Win32_Fog_MKV_MTB{
	meta:
		description = "Ransom:Win32/Fog.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 99 b9 05 00 00 00 f7 f9 33 74 d5 ac 33 7c d5 ?? 8b 55 fc 8b c2 31 30 8d 40 28 31 78 dc 83 e9 01 75 ?? 83 c2 08 8d 71 05 43 89 55 fc 83 6d f8 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}