
rule Ransom_Win32_Stopcrypt_YAJ_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 03 45 ?? 89 45 ?? 8b 45 f8 89 45 ec 8b 45 f4 01 45 fc 8b 45 fc 31 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}