
rule Trojan_Win64_Lazy_LMD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 3d 0f 97 04 00 67 8d 04 09 48 8d 3c c7 48 8b 77 08 48 8b 46 08 48 89 47 08 48 89 38 48 39 c7 75 1b b8 fe ff ff ff d3 c0 4c 8d ?? ?? ?? ?? ?? 41 21 04 90 90 75 } //15
		$a_03_1 = {48 8b 45 30 c6 00 20 48 83 c0 01 48 89 45 30 c6 00 78 48 83 c0 01 48 89 45 30 c6 00 20 48 83 c0 01 48 89 45 30 8b c6 48 c1 e0 09 48 8d ?? ?? ?? ?? ?? ?? 8b cf 48 03 c9 8b 0c c8 48 8b 55 30 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}