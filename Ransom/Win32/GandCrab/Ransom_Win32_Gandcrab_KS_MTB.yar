
rule Ransom_Win32_Gandcrab_KS_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {30 84 1e 00 fe ff ff 57 57 57 57 ff 15 90 01 04 46 3b 75 08 7c d7 90 00 } //0a 00 
		$a_00_1 = {89 45 fc 0f be 00 3d b3 01 00 00 74 07 ff 55 fc } //00 00 
	condition:
		any of ($a_*)
 
}