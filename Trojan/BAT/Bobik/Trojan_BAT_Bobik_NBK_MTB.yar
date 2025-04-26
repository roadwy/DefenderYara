
rule Trojan_BAT_Bobik_NBK_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 e8 01 00 0a 58 28 ?? ?? 00 0a 61 69 61 69 fe ?? ?? 00 61 5e } //5
		$a_01_1 = {4e 20 53 70 6f 6f 66 65 72 } //1 N Spoofer
		$a_01_2 = {4e 65 6f 78 20 53 70 6f 6f 66 65 72 } //1 Neox Spoofer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_Bobik_NBK_MTB_2{
	meta:
		description = "Trojan:BAT/Bobik.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 7e ?? 00 00 04 28 ?? 00 00 06 00 28 ?? 00 00 0a 14 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7e ?? 00 00 04 28 ?? 00 00 06 00 28 ?? 00 00 0a 6f ?? 00 00 0a 26 } //5
		$a_01_1 = {77 77 63 64 2e 65 78 65 } //1 wwcd.exe
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 69 00 6e 00 2e 00 70 00 6e 00 67 00 } //1 Windows\Win.png
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}