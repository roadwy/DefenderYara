
rule Trojan_Win32_XWormRAT_A_MTB{
	meta:
		description = "Trojan:Win32/XWormRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 72 14 8b 55 ?? 8b 52 0c 8a 04 08 32 04 32 8b 4d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}