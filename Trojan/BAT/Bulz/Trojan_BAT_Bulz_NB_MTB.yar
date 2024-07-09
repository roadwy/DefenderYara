
rule Trojan_BAT_Bulz_NB_MTB{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 37 01 00 04 02 28 ?? ?? 00 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 06 26 02 16 } //5
		$a_01_1 = {56 61 6e 69 6c 6c 61 52 61 74 2e 65 78 65 } //1 VanillaRat.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}