
rule Ransom_Win32_StopCrypt_PE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 90 01 01 8b 08 33 4d 90 01 01 8b 55 90 01 01 89 0a 5d 90 00 } //01 00 
		$a_03_1 = {c1 e2 04 89 90 01 01 e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 90 02 0a c7 05 90 02 0a 8b 90 01 01 f4 8b 8d 90 02 04 d3 90 01 01 89 90 01 01 ec 8b 90 01 01 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}