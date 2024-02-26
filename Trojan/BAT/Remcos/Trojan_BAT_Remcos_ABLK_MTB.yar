
rule Trojan_BAT_Remcos_ABLK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {07 11 09 03 11 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 11 06 11 09 11 07 5d 91 61 d2 9c 11 08 18 58 13 08 11 08 06 3f 90 01 03 ff 07 2a 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {54 6f 42 79 74 65 } //00 00  ToByte
	condition:
		any of ($a_*)
 
}