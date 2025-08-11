
rule Trojan_Win32_Lazy_SCP_MTB{
	meta:
		description = "Trojan:Win32/Lazy.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 08 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 51 0c 31 c9 29 c1 31 c0 29 d0 01 c1 31 c0 29 c8 89 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}