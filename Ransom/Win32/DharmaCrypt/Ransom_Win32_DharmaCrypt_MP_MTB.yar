
rule Ransom_Win32_DharmaCrypt_MP_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 11 0f b6 45 ff 0f b6 4d f7 03 c1 0f b6 c0 8b 4d f0 0f b6 04 01 33 d0 8b 4d 10 } //00 00 
	condition:
		any of ($a_*)
 
}