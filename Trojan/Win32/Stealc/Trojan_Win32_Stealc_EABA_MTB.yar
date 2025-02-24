
rule Trojan_Win32_Stealc_EABA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.EABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 84 3a 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 39 81 3d ?? ?? ?? ?? 90 04 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}