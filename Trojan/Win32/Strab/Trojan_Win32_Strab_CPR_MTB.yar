
rule Trojan_Win32_Strab_CPR_MTB{
	meta:
		description = "Trojan:Win32/Strab.CPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 30 8b c6 83 e0 ?? 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d d0 88 04 31 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}