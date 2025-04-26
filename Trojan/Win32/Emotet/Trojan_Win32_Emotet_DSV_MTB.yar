
rule Trojan_Win32_Emotet_DSV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {b8 ab aa aa aa f7 e6 8b ce d1 ea 8d 04 52 2b c8 8a 44 0d ?? 30 86 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 72 } //2
		$a_81_1 = {59 56 33 57 4e 32 4a 36 59 42 4d 43 47 56 49 44 38 55 55 } //1 YV3WN2J6YBMCGVID8UU
		$a_81_2 = {51 5a 4d 4a 47 47 34 4d 48 50 48 4b 36 45 5a 47 30 45 53 } //1 QZMJGG4MHPHK6EZG0ES
	condition:
		((#a_02_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}