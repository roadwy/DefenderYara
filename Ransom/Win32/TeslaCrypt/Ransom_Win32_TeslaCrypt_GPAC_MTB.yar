
rule Ransom_Win32_TeslaCrypt_GPAC_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 44 33 54 24 44 8b 74 24 1c 89 54 24 44 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}