
rule Trojan_Win32_StealC_NE_MTB{
	meta:
		description = "Trojan:Win32/StealC.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {70 6f 74 69 6e 61 6c 69 78 61 6d 75 6d 75 78 6f 6c 6f 7a 61 79 } //2 potinalixamumuxolozay
		$a_81_1 = {73 69 62 65 70 65 79 65 64 75 70 75 63 69 73 } //1 sibepeyedupucis
		$a_81_2 = {6a 75 74 75 73 65 6e 61 76 6f 63 69 62 69 79 61 78 75 6e 6f 6b 75 62 69 79 65 66 65 74 } //1 jutusenavocibiyaxunokubiyefet
		$a_81_3 = {6e 65 6d 61 67 75 74 69 6d 65 62 6f 6e 65 66 6f 74 65 6b 6f 6e 65 62 } //1 nemagutimebonefotekoneb
		$a_81_4 = {62 61 68 75 6a 69 6a 75 64 75 6e 6f 67 69 6b 61 77 61 74 69 68 6f 68 65 6c 75 6a 6f 66 } //1 bahujijudunogikawatihohelujof
		$a_81_5 = {6d 75 66 6f 6c 6f 6d 65 72 61 67 61 6b 6f 77 75 62 69 63 69 67 65 72 6f } //1 mufolomeragakowubicigero
		$a_81_6 = {6d 73 69 6d 67 33 32 2e 64 6c 6c } //1 msimg32.dll
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}