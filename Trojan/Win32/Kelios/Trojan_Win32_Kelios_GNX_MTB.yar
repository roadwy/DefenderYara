
rule Trojan_Win32_Kelios_GNX_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 cb 68 02 ?? ?? ?? d0 c1 fe c1 d0 c9 c1 34 24 ?? 80 d1 ?? f6 d1 32 d9 c0 64 24 ?? 22 81 ed ?? ?? ?? ?? 66 89 4c 25 ?? f6 54 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}