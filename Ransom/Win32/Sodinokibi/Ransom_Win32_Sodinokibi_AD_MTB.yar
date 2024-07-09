
rule Ransom_Win32_Sodinokibi_AD_MTB{
	meta:
		description = "Ransom:Win32/Sodinokibi.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec e9 90 0a 07 00 55 8b ec 90 13 8b 75 08 90 13 8b 7d 0c 90 13 8b 55 10 90 13 b1 ?? 90 13 ac } //5
	condition:
		((#a_03_0  & 1)*5) >=1
 
}