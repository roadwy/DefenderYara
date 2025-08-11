
rule Trojan_Win32_Spy_Casbaneiro_GA{
	meta:
		description = "Trojan:Win32/Spy.Casbaneiro.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 83 e8 02 74 21 2d 10 01 00 00 75 23 8b 45 14 50 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ?? ?? ?? ?? ?? 89 45 fc eb 28 6a 00 ?? ?? ?? ?? ?? eb 1a 8b 45 14 50 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ?? ?? ?? ?? ?? 89 45 fc eb 05 33 c0 89 45 fc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}