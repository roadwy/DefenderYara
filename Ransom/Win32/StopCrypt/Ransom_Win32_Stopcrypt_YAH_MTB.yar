
rule Ransom_Win32_Stopcrypt_YAH_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 2b 7c 24 10 81 c3 } //00 00 
	condition:
		any of ($a_*)
 
}