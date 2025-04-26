
rule Trojan_WinNT_Flosyt_A{
	meta:
		description = "Trojan:WinNT/Flosyt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 48 08 8b 00 8b 15 ?? ?? ?? ?? 3b 54 88 fc 74 04 e2 f8 eb 0f 8d 44 88 fc a3 ?? ?? ?? ?? c7 00 } //1
		$a_03_1 = {83 7c 24 04 05 75 0e 8b 74 24 08 8b 3c 24 c7 04 24 ?? ?? ?? ?? ff 25 ?? ?? ?? ?? 85 c0 75 ?? eb ?? 03 36 39 46 3c 74 ?? 8b 56 3c 81 3a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}