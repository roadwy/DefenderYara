
rule Trojan_BAT_RedLine_NZY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 64 64 73 73 73 73 73 73 73 73 73 73 73 73 73 73 66 73 73 73 73 73 73 73 66 66 73 64 64 68 66 68 6b 66 6a } //01 00  jddssssssssssssssfsssssssffsddhfhkfj
		$a_01_1 = {73 64 64 64 64 66 66 73 68 64 6a 66 66 66 66 66 67 6a 73 6b 64 67 73 61 63 73 61 66 70 } //01 00  sddddffshdjfffffgjskdgsacsafp
		$a_01_2 = {6a 63 66 73 66 64 73 61 66 73 64 67 6b 66 66 66 66 } //01 00  jcfsfdsafsdgkffff
		$a_01_3 = {66 68 64 64 73 66 66 68 73 73 } //01 00  fhddsffhss
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}