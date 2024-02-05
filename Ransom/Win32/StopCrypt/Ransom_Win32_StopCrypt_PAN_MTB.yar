
rule Ransom_Win32_StopCrypt_PAN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 8b 45 90 02 02 c1 e8 05 89 45 90 01 01 8b 45 90 01 01 33 f1 8b 90 02 05 03 c1 33 c6 83 3d 90 01 04 27 c7 05 90 01 04 2e ce 50 91 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}