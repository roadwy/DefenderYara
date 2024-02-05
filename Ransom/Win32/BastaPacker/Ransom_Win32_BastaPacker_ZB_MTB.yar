
rule Ransom_Win32_BastaPacker_ZB_MTB{
	meta:
		description = "Ransom:Win32/BastaPacker.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 d0 c1 c2 08 90 13 90 13 ac 90 13 84 c0 90 13 8b c2 90 13 5e 5a 90 13 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}