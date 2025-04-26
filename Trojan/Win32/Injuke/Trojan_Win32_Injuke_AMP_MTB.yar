
rule Trojan_Win32_Injuke_AMP_MTB{
	meta:
		description = "Trojan:Win32/Injuke.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 13 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 8b f0 83 c6 04 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}