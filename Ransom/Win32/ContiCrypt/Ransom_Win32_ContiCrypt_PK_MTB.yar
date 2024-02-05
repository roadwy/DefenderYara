
rule Ransom_Win32_ContiCrypt_PK_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 06 ac 04 90 02 40 32 c1 32 c1 90 02 40 32 c1 2a c1 2a c1 90 02 90 aa 4a 0f 85 90 02 04 8b ec 5d c2 0c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}