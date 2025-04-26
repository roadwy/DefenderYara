
rule Trojan_Win64_RustStealer_GTT_MTB{
	meta:
		description = "Trojan:Win64/RustStealer.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 20 3e 20 6e ?? 6c 0a 64 65 ?? 20 22 22 0a 64 65 6c 20 22 25 ?? ?? ?? ?? 0a 00 } //10
		$a_01_1 = {76 65 6c 20 63 72 69 61 72 20 6f 20 61 72 71 75 69 76 6f 20 2e 62 61 74 } //1 vel criar o arquivo .bat
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}