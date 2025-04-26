
rule Trojan_BAT_SmokeLoader_GFM_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 2b 14 2b 19 2b 1e 1e 2d 06 26 16 2d ee de 22 2b 1a 1d 2c f6 2b f4 28 ?? ?? ?? 06 2b e5 28 ?? ?? ?? 2b 2b e0 28 ?? ?? ?? 2b 2b db 0a 2b e3 } //10
		$a_80_1 = {31 39 32 2e 33 2e 32 37 2e 31 34 30 } //192.3.27.140  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}