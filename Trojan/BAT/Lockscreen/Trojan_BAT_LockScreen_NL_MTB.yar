
rule Trojan_BAT_LockScreen_NL_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 0a 72 89 00 00 70 0b 06 07 28 ?? 00 00 0a 00 72 03 01 00 70 06 28 ?? 00 00 0a 26 } //3
		$a_01_1 = {4e 79 61 6e 20 43 61 74 2e 65 78 65 } //1 Nyan Cat.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}