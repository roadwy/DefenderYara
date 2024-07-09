
rule Trojan_Win32_SmokeLoader_PADM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 ff 2d 75 06 6a 00 6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 1e 83 ff 0f 75 08 } //1
		$a_03_1 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 ?? ?? ?? ?? 0f af 04 24 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 59 c3 } //1
		$a_03_2 = {ff d7 6a 00 ff d3 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 81 fe fc 6a 17 00 0f 8f 7d 02 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}