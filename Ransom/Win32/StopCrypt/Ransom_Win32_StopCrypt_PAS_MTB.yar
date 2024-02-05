
rule Ransom_Win32_StopCrypt_PAS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 08 88 0a c3 } //01 00 
		$a_00_1 = {cc cc cc cc cc cc cc cc cc cc cc 33 c9 c7 40 18 0f 00 00 00 89 48 14 88 48 04 c3 } //03 00 
		$a_03_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 ff 15 90 01 04 e8 90 01 04 8b 4c 90 01 02 30 04 31 81 ff 90 01 04 75 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 6f 
	condition:
		any of ($a_*)
 
}