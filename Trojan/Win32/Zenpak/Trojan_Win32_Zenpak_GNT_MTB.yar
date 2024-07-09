
rule Trojan_Win32_Zenpak_GNT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 20 31 c2 4a 4a 83 f0 ?? e8 ?? ?? ?? ?? c3 01 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 31 d0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}