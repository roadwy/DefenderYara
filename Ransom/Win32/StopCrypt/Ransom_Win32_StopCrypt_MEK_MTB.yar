
rule Ransom_Win32_StopCrypt_MEK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 45 f0 89 5d f4 2b f8 25 90 02 04 81 6d f4 90 02 04 81 45 f4 90 02 04 8b 4d dc 8b c7 c1 e8 90 02 01 89 45 f0 8d 45 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}