
rule Trojan_Win32_Emotet_DHE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 53 8d 34 07 e8 ?? ?? ?? ?? 59 33 d2 8b c8 8b c7 f7 f1 8a 04 1a 30 06 47 3b 7c 24 18 75 d4 } //2
		$a_01_1 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 } //1 VirtualAlloc
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}