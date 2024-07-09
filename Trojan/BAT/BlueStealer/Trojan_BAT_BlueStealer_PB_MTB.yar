
rule Trojan_BAT_BlueStealer_PB_MTB{
	meta:
		description = "Trojan:BAT/BlueStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 72 2a 05 00 70 72 2e 05 00 70 6f ?? ?? 00 0a 0b 73 c3 00 00 0a 0c 16 0d 2b 23 00 07 09 18 6f ?? ?? 00 0a 20 03 02 00 00 28 ?? ?? 00 0a 13 05 08 } //1
		$a_01_1 = {50 00 53 00 4f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 PSO.Properties.Resources
		$a_01_2 = {58 6e 6f 72 } //1 Xnor
		$a_01_3 = {66 47 74 48 2e 65 78 65 } //1 fGtH.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}