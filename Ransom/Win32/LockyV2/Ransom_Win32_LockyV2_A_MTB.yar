
rule Ransom_Win32_LockyV2_A_MTB{
	meta:
		description = "Ransom:Win32/LockyV2.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c8 f7 d1 8b 95 90 01 02 ff ff 2b 95 90 01 02 ff ff 81 f2 90 01 04 0f 31 33 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}