
rule Ransom_Win32_Vohuk_PC_MTB{
	meta:
		description = "Ransom:Win32/Vohuk.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 90 01 01 89 85 90 01 04 33 c2 c1 c0 90 01 01 89 45 90 01 01 89 45 90 01 01 03 c1 33 f8 89 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 c1 c7 07 89 7d d8 89 bd 90 01 04 8b 7d ec 03 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}