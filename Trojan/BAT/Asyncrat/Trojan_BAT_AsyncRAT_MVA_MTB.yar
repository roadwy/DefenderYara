
rule Trojan_BAT_AsyncRAT_MVA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 65 6e 74 41 6e 79 2e 65 78 65 } //ClientAny.exe  2
		$a_80_1 = {56 65 6e 6f 6d 52 41 54 42 79 56 65 6e 6f 6d } //VenomRATByVenom  2
		$a_80_2 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //RunAntiAnalysis  1
		$a_80_3 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 75 20 73 79 73 74 65 6d 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } ///c schtasks /create /f /sc onlogon /ru system /rl highest /tn  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}