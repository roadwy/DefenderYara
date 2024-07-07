
rule Trojan_BAT_Starter_EDV_MTB{
	meta:
		description = "Trojan:BAT/Starter.EDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 24 4c 69 6d 65 55 53 42 5c } //\$LimeUSB\  3
		$a_80_1 = {25 55 53 42 25 } //%USB%  3
		$a_80_2 = {4c 69 6d 65 55 53 42 5c 50 61 79 6c 6f 61 64 2e 76 62 73 } //LimeUSB\Payload.vbs  3
		$a_80_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //System.Reflection  3
		$a_80_4 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //AssemblyTrademarkAttribute  3
		$a_80_5 = {47 75 69 64 41 74 74 72 69 62 75 74 65 } //GuidAttribute  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}