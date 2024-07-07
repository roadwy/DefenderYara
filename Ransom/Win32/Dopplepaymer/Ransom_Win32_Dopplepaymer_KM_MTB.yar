
rule Ransom_Win32_Dopplepaymer_KM_MTB{
	meta:
		description = "Ransom:Win32/Dopplepaymer.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 c0 89 45 90 01 01 eb 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8a 14 01 8b 75 90 01 01 88 14 06 83 c0 01 8b 7d 90 01 01 39 f8 89 45 90 00 } //1
		$a_02_1 = {8a 14 01 8b 75 90 01 01 88 14 06 83 c0 01 8b 7d 90 01 01 39 f8 89 45 90 01 01 74 90 01 01 eb 90 01 01 31 c0 89 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}