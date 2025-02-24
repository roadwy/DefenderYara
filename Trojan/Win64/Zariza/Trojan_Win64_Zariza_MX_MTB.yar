
rule Trojan_Win64_Zariza_MX_MTB{
	meta:
		description = "Trojan:Win64/Zariza.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 69 6a 61 63 6b 2e 64 6c 6c } //1 hijack.dll
		$a_01_1 = {7a 69 67 2d 6c 6f 61 64 65 72 2e 64 6c 6c } //1 zig-loader.dll
		$a_01_2 = {64 00 65 00 63 00 6f 00 2e 00 64 00 6c 00 6c 00 } //2 deco.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}