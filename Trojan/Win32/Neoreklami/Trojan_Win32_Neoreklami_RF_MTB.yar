
rule Trojan_Win32_Neoreklami_RF_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 74 66 69 6b 77 20 6a 65 6c 65 20 70 63 77 61 67 78 20 6a 66 75 20 6e 6b 74 70 78 63 20 75 6a 71 20 70 67 78 73 68 6b 78 74 20 6d 71 65 75 74 6c 71 62 20 67 6f 74 20 67 78 72 6c 79 6c 74 } //1 ctfikw jele pcwagx jfu nktpxc ujq pgxshkxt mqeutlqb got gxrlylt
		$a_01_1 = {70 77 77 79 20 77 74 73 6a 6d 72 78 20 64 67 61 20 75 6a 6c 70 76 20 71 78 6b 78 6f 75 63 6e 20 77 71 62 63 20 69 76 6d 63 63 } //1 pwwy wtsjmrx dga ujlpv qxkxoucn wqbc ivmcc
		$a_01_2 = {6e 70 62 20 78 76 63 61 20 78 67 62 76 63 67 65 74 6c 20 73 6b 77 6b 71 61 77 69 } //1 npb xvca xgbvcgetl skwkqawi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}