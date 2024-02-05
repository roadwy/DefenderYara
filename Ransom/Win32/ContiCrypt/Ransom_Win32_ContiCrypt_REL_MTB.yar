
rule Ransom_Win32_ContiCrypt_REL_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.REL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 2b c8 6b c1 90 01 01 99 f7 fb 8d 42 7f 99 f7 fb 88 54 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}