
rule Trojan_Win32_Junkoil_A{
	meta:
		description = "Trojan:Win32/Junkoil.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 c0 74 31 68 ?? ?? 40 00 6a 00 68 01 00 1f 00 e8 ?? ?? ff ff 85 c0 75 ?? 68 ?? ?? 40 00 6a 00 68 66 66 66 66 68 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}