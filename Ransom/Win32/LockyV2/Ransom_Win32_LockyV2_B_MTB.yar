
rule Ransom_Win32_LockyV2_B_MTB{
	meta:
		description = "Ransom:Win32/LockyV2.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 d2 66 55 66 5d 8b c8 ff b5 90 01 01 fe ff ff 8f 85 90 01 01 fe ff ff ba 90 01 04 8d 00 0f 31 8d 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}