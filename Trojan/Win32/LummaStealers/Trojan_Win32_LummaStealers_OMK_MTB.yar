
rule Trojan_Win32_LummaStealers_OMK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealers.OMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 56 64 8b 3d 30 00 00 00 8b 7f 0c 8b 77 0c 8b 06 8b 00 8b 40 18 a3 70 14 43 00 5e 5f 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}