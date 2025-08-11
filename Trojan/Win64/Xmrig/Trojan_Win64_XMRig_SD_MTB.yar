
rule Trojan_Win64_XMRig_SD_MTB{
	meta:
		description = "Trojan:Win64/XMRig.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 05 b7 da 00 00 ee d9 d2 73 e8 ?? ?? ?? ?? c7 05 a8 da 00 00 ec 07 75 ec e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}