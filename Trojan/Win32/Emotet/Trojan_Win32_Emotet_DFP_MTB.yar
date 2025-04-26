
rule Trojan_Win32_Emotet_DFP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 e1 c1 ea 04 8d 04 92 03 c0 03 c0 8b d1 2b d0 8a 04 1a 30 04 31 [0-04] 3b cf 75 } //1
		$a_81_1 = {72 44 41 7a 78 73 73 47 41 47 64 64 45 41 53 5a 44 } //1 rDAzxssGAGddEASZD
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}