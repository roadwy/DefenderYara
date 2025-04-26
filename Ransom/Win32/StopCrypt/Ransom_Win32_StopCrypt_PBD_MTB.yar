
rule Ransom_Win32_StopCrypt_PBD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c7 c1 e0 04 03 45 ?? 8d 0c 3b 33 c1 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}