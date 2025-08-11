
rule Trojan_Win32_Tofsee_EAWE_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 89 26 9e 03 00 88 08 81 3d ?? ?? ?? ?? 8a 01 00 00 75 20 6a 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}