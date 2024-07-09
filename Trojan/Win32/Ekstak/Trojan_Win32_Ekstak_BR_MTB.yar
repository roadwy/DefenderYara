
rule Trojan_Win32_Ekstak_BR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 20 02 00 00 6a 20 8d 4c 24 38 6a 02 51 89 5c 24 3c 88 5c 24 40 88 5c 24 41 88 5c 24 42 88 5c 24 43 88 5c 24 44 c6 44 24 45 05 89 5c 24 30 ff 15 ?? ?? ?? 00 85 c0 75 } //2
		$a_03_1 = {8d 4c 24 08 51 68 0a 00 02 00 50 ff 15 ?? ?? ?? 00 85 c0 75 } //1
		$a_03_2 = {8b f0 33 f7 ff 15 ?? ?? ?? 00 8d 4c 24 10 8b f8 51 33 fe ff 15 ?? ?? ?? 00 8b 4c 24 14 8b 44 24 10 33 c8 8b c1 33 cf 5f 81 f9 4e e6 40 bb 5e 75 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}