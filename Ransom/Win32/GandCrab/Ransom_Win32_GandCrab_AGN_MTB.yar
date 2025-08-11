
rule Ransom_Win32_GandCrab_AGN_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.AGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 83 c2 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}