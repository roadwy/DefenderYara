
rule Trojan_BAT_DarkTortilla_RPAC_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-06] 2e 67 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 90 1b 00 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //100
		$a_80_1 = {57 69 6e 64 6f 77 73 41 70 70 31 } //WindowsApp1  1
	condition:
		((#a_03_0  & 1)*100+(#a_80_1  & 1)*1) >=101
 
}