
rule Trojan_Win32_Guloader_RPS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 85 c9 31 1c 08 66 85 c0 83 c1 04 de e8 eb 53 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}