
rule Trojan_Win32_Emotet_RD{
	meta:
		description = "Trojan:Win32/Emotet.RD,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 67 72 6f 75 6e 64 5c 61 70 70 6c 65 5c 62 65 65 6e 5c 66 6c 61 74 5c 53 75 72 70 72 69 73 65 5c 6d 61 72 6b 65 74 5c 74 6f 6f 6b 5c 73 6c 61 76 65 5c 6f 6e 63 65 74 72 69 61 6e 67 6c 65 2e 70 64 62 } //00 00  c:\ground\apple\been\flat\Surprise\market\took\slave\oncetriangle.pdb
	condition:
		any of ($a_*)
 
}