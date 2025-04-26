
rule Trojan_Win32_Ekstak_RY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 68 a0 c0 64 00 68 54 c0 64 00 e8 ?? ?? fb ff 8b f0 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}