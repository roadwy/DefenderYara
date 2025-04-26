
rule Trojan_Win32_Tofsee_EAEC_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 94 01 01 24 0a 00 8b 0d ?? ?? ?? ?? 88 14 01 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}