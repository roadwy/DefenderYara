
rule Trojan_Win32_Emotet_PSK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ?? ?? 8a 94 15 ?? ?? ?? ?? 30 10 } //1
		$a_81_1 = {66 48 77 52 6b 4d 31 79 30 67 64 68 55 7a 6d 34 31 4c 4c 53 4e 79 74 41 62 69 50 30 45 44 6a 4b 4a 4f 47 61 51 } //1 fHwRkM1y0gdhUzm41LLSNytAbiP0EDjKJOGaQ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}