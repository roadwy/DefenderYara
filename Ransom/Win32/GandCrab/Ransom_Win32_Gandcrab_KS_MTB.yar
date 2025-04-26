
rule Ransom_Win32_Gandcrab_KS_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 84 1e 00 fe ff ff 57 57 57 57 ff 15 ?? ?? ?? ?? 46 3b 75 08 7c d7 } //10
		$a_00_1 = {89 45 fc 0f be 00 3d b3 01 00 00 74 07 ff 55 fc } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}