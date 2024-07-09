
rule Trojan_Win32_TrickBot_SB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 50 6a 40 6a 05 56 ff ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00 8d 4c 24 0c 6a 01 51 56 c7 44 24 18 e9 00 00 00 ff d7 8d 44 24 08 6a 04 8b 54 24 1c 50 2b d6 70 ?? 83 ea 05 70 ?? 83 c6 01 89 54 24 10 70 ?? 56 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}