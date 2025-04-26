
rule Ransom_Win32_StopCrypt_CSK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8b 55 fc d3 e8 03 45 d0 89 45 f0 89 45 f4 8d 04 37 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}