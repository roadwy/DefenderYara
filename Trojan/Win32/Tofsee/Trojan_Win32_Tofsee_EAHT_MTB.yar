
rule Trojan_Win32_Tofsee_EAHT_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 94 31 1b 1b 01 00 8b 0d ?? ?? ?? ?? 88 14 31 3d a8 00 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}