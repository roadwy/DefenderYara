
rule Ransom_Win32_StopCrypt_SLQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b de c1 e3 90 01 01 03 5d 90 01 01 8d 04 32 33 cb 33 c8 89 45 90 01 01 89 4d 90 01 01 8b 45 0c 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 45 90 01 01 89 45 90 00 } //01 00 
		$a_03_1 = {8b 45 f4 33 45 90 01 01 83 65 90 01 02 2b f0 8b 45 90 01 01 01 45 90 01 01 2b 55 90 01 01 ff 4d 90 01 01 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}