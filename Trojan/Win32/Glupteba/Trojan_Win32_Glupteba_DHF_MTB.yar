
rule Trojan_Win32_Glupteba_DHF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 7d 0c 00 7c 26 8b 55 ?? 03 55 ?? 0f be 1a e8 ?? ?? ?? ?? 0f b6 c0 33 d8 8b 4d ?? 03 4d ?? 88 19 8b 55 0c 83 ea 01 89 55 0c eb d4 } //1
		$a_02_1 = {33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 21 06 00 00 75 1f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}