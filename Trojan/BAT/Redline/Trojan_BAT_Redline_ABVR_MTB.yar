
rule Trojan_BAT_Redline_ABVR_MTB{
	meta:
		description = "Trojan:BAT/Redline.ABVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 18 5b 8d ?? 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //3
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 39 38 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp98.Form1.resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}