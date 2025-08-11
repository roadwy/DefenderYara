
rule Trojan_Win32_Tinba_RLB_MTB{
	meta:
		description = "Trojan:Win32/Tinba.RLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 38 32 4c 24 5b 88 4c 24 4f 8a 4c 24 4f 6a 05 56 88 4c 04 2c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}