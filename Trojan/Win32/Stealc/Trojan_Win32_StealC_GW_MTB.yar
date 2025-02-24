
rule Trojan_Win32_StealC_GW_MTB{
	meta:
		description = "Trojan:Win32/StealC.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 6c 24 0c 3c 8a 44 24 0c 30 04 3b 83 fd 0f 75 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}