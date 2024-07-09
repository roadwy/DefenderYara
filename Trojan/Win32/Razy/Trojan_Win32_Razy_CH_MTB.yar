
rule Trojan_Win32_Razy_CH_MTB{
	meta:
		description = "Trojan:Win32/Razy.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 ea 31 13 81 c7 [0-04] 81 c3 04 00 00 00 4e 39 c3 75 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}