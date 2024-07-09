
rule Trojan_WinNT_Rovnix_A{
	meta:
		description = "Trojan:WinNT/Rovnix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 42 4f 4f 54 2e 53 59 53 00 [0-30] 56 46 41 54 31 2e 31 20 } //1
		$a_03_1 = {8b 43 04 6a 09 59 bf ?? ?? ?? ?? 8d 70 03 33 d2 f3 a6 c7 45 fc 7b 00 00 c0 0f 85 ?? ?? ?? ?? 8b 75 08 0f b7 50 0b 8b 4e 14 3b d1 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}