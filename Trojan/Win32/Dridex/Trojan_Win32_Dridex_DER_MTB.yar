
rule Trojan_Win32_Dridex_DER_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c6 8d 04 83 89 44 24 1c 66 a3 ?? ?? ?? ?? 8b 7c 24 18 8b 44 24 10 05 ?? ?? ?? ?? 89 44 24 10 89 07 6b fb 1d a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 83 c7 09 03 f9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}