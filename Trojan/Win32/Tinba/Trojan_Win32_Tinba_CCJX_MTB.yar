
rule Trojan_Win32_Tinba_CCJX_MTB{
	meta:
		description = "Trojan:Win32/Tinba.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ac c1 e2 ed 33 55 a4 89 55 cc c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d b8 03 4d c8 8b 75 d8 d3 e6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}