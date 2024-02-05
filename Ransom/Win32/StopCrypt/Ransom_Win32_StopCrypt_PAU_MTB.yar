
rule Ransom_Win32_StopCrypt_PAU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 33 c7 83 3d 90 01 04 27 c7 05 90 01 04 2e ce 50 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}