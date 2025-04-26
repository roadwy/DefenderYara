
rule Trojan_Win32_Johnnie_OJ_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.OJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {34 f9 be e9 3b 41 00 bb ?? ?? ?? ?? 88 07 2b f7 2b df 8d 4b ?? 02 ca 32 0c 16 2a 0a 80 f1 ?? c0 c9 ?? 32 0a 88 4a 01 4a 8d 04 13 83 f8 ?? 7d e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}