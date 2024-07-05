
rule Ransom_Win32_Filecoder_PAEB_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 45 0c 8b 4d 08 ba b7 bc 00 00 c7 44 24 28 24 4d 00 00 be 24 4d 00 00 c7 44 24 20 13 78 00 00 bf 13 78 00 00 c7 44 24 34 00 00 00 00 c7 44 24 30 38 2a 00 00 8b 5c 24 28 88 44 24 13 89 f0 35 87 59 00 00 89 44 24 2c 29 da 39 fa 89 74 24 0c 89 4c 24 08 76 } //02 00 
		$a_01_1 = {35 c9 70 fe 5a be c9 43 00 00 89 44 24 34 89 f8 89 54 24 30 f7 e6 8b 74 24 48 69 f6 c9 43 00 00 01 f2 } //00 00 
	condition:
		any of ($a_*)
 
}