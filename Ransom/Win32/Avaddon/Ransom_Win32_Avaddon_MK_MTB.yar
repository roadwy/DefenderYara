
rule Ransom_Win32_Avaddon_MK_MTB{
	meta:
		description = "Ransom:Win32/Avaddon.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 8d 4d bc 34 ?? 04 ?? 34 ?? 0f b6 c0 50 e8 ?? ?? ?? ?? 46 3b f7 75 e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}