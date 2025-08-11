
rule Trojan_Win32_Upatre_PGU_MTB{
	meta:
		description = "Trojan:Win32/Upatre.PGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 40 40 68 ?? ?? ?? ?? ff 00 6a 40 40 40 00 89 ?? ?? ?? ?? ff 40 40 30 68 6a 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}