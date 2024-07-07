
rule Trojan_Win32_Tinba_MI_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 81 f3 75 33 66 89 5c 24 6a 66 89 cb 66 09 df 66 89 7c 24 5e 66 89 c7 66 29 f7 66 89 bc 24 0a 02 00 00 8b 44 24 20 39 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}