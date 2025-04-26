
rule Trojan_Win64_CobaltStrike_MI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 65 76 61 73 69 6f 6e 43 5f 67 6f 5c 77 6f 72 6b 69 6e 67 53 70 61 63 65 } //1 Projects\evasionC_go\workingSpace
		$a_00_1 = {5f 73 65 68 5f 66 69 6c 74 65 72 5f 64 6c 6c } //1 _seh_filter_dll
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_MI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {42 64 70 6c 54 6c 4b 50 6c 49 77 4a 6a 58 5a 56 72 65 64 4a 4e 76 49 4a 65 7a } //1 BdplTlKPlIwJjXZVredJNvIJez
		$a_01_1 = {42 69 79 6d 4a 5a 71 56 6d 6c 59 42 } //1 BiymJZqVmlYB
		$a_01_2 = {42 6f 65 76 56 42 61 63 65 6a 53 6d 77 63 5a } //1 BoevVBacejSmwcZ
		$a_01_3 = {44 47 69 76 53 76 58 75 49 72 42 48 4e 44 43 55 50 7a } //1 DGivSvXuIrBHNDCUPz
		$a_01_4 = {44 5a 61 46 52 53 5a } //1 DZaFRSZ
		$a_01_5 = {44 6b 4b 62 44 52 58 45 50 59 4b 67 49 58 } //1 DkKbDRXEPYKgIX
		$a_01_6 = {44 6d 56 73 74 4a 42 49 66 75 6f 41 63 78 } //1 DmVstJBIfuoAcx
		$a_01_7 = {46 6c 48 42 4c 65 48 70 54 49 6c 4c 42 4f 74 45 71 75 } //1 FlHBLeHpTIlLBOtEqu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}