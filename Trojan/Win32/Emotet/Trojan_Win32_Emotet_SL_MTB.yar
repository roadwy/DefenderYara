
rule Trojan_Win32_Emotet_SL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6e 54 74 65 72 24 37 } //1 nTter$7
		$a_81_1 = {57 52 4a 45 52 68 57 40 } //1 WRJERhW@
		$a_81_2 = {54 48 52 45 2e 70 64 62 } //1 THRE.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}