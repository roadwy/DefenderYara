
rule Ransom_Win32_Clop_A_MTB{
	meta:
		description = "Ransom:Win32/Clop.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff ff 48 03 00 00 73 90 01 01 8b 90 01 02 ff ff ff 8b 90 01 06 89 90 01 02 ff ff ff c7 85 90 01 04 00 00 00 00 90 02 06 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 2b 90 01 02 ff ff ff 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 83 90 01 01 50 89 90 01 02 ff ff ff c1 85 90 01 01 ff ff ff 05 8b 90 01 02 ff ff ff 33 90 01 02 ff ff ff 89 90 01 02 ff ff ff 8b 90 01 02 ff ff ff 8b 90 02 05 8b 90 01 02 ff ff ff 89 90 01 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}