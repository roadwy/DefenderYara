
rule Trojan_Win32_SystemBC_psyW_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 02 66 85 c9 75 ?? e8 95 ?? ?? ?? ?? c9 68 ?? ?? ?? 00 51 8d 54 24 ?? 52 66 89 4c 24 ?? e8 ?? ?? ?? 00 83 c4 ?? 8d 44 24 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}