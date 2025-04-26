
rule Ransom_Win32_Locky_TOZ_MTB{
	meta:
		description = "Ransom:Win32/Locky.TOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 2d 04 00 00 b8 39 02 00 00 8d bc 36 ?? ?? ?? ?? 2b c6 d1 e0 2b f8 03 cf 8b 7d 08 88 14 3b 8d 91 77 fd ff ff 85 d2 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}