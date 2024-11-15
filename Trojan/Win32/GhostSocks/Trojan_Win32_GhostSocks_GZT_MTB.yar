
rule Trojan_Win32_GhostSocks_GZT_MTB{
	meta:
		description = "Trojan:Win32/GhostSocks.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 5f 45 31 46 e0 32 d7 68 ?? ?? ?? ?? a8 44 03 58 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}