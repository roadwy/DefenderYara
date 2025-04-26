
rule Ransom_Win32_RapidRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/RapidRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 8b 4d 08 8b 55 ?? 01 ca 0f b6 12 89 d1 8b 55 f4 31 ca 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}