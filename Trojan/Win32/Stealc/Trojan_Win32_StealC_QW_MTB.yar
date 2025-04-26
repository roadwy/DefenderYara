
rule Trojan_Win32_StealC_QW_MTB{
	meta:
		description = "Trojan:Win32/StealC.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 c4 30 04 3b 83 7d ?? 0f 59 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}