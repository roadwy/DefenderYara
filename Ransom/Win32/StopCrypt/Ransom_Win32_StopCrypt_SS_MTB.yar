
rule Ransom_Win32_StopCrypt_SS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 f8 8b 4d ?? 33 4d ?? 8b 45 ?? 33 c1 2b f8 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}