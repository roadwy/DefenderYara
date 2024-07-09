
rule Trojan_BAT_Injuke_NIA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 22 01 00 0a 6f ?? ?? 00 0a a2 25 18 73 ?? ?? 00 0a 06 1e 06 6f ?? ?? 00 0a 1e da 6f ?? ?? 00 0a 28 ?? ?? 00 0a } //5
		$a_01_1 = {33 00 52 00 47 00 4b 00 68 00 37 00 70 00 } //1 3RGKh7p
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}