
rule Ransom_Win32_Avaddon_MK_MTB{
	meta:
		description = "Ransom:Win32/Avaddon.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 8d 4d bc 34 90 01 01 04 90 01 01 34 90 01 01 0f b6 c0 50 e8 90 01 04 46 3b f7 75 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}