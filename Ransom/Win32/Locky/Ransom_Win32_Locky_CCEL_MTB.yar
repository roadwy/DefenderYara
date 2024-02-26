
rule Ransom_Win32_Locky_CCEL_MTB{
	meta:
		description = "Ransom:Win32/Locky.CCEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8b 95 90 01 04 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 c1 e8 10 32 04 0a 8d 95 90 01 04 52 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}