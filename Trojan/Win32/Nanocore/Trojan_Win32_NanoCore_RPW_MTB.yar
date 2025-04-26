
rule Trojan_Win32_NanoCore_RPW_MTB{
	meta:
		description = "Trojan:Win32/NanoCore.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a c8 80 c1 2b 32 c8 fe c1 02 c8 c0 c1 02 32 c8 02 c8 32 c8 80 c1 6b 88 88 ?? ?? ?? ?? 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}