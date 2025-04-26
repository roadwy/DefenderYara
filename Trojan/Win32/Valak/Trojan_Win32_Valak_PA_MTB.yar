
rule Trojan_Win32_Valak_PA_MTB{
	meta:
		description = "Trojan:Win32/Valak.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 6c 24 14 05 ?? ?? ?? ?? 89 84 2a ?? ?? ?? ?? 0f b6 15 ?? ?? ?? 00 a3 d4 54 4d 00 0f b6 05 ?? ?? ?? 00 2b c2 3d ?? ?? 00 00 89 44 24 10 74 26 a1 ?? ?? ?? 00 8a d0 02 d3 80 ea 03 88 15 ?? ?? ?? 00 8b d7 c1 e2 04 03 d7 2b d1 03 d6 } //10
		$a_02_1 = {66 29 0c 45 ?? ?? ?? 00 8b df 0f af de 69 db 37 09 00 00 83 e8 01 85 c0 8b f3 7f } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=1
 
}