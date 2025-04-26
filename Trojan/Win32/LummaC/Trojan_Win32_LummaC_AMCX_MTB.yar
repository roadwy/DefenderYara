
rule Trojan_Win32_LummaC_AMCX_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 18 89 65 ?? 83 ec 18 89 65 ?? c7 00 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c7 40 08 ?? ?? ?? ?? c7 40 0c ?? ?? ?? ?? c7 40 10 ?? ?? ?? ?? 31 c9 90 90 [0-15] 31 [0-2f] fe c2 88 14 08 [0-0f] 83 e2 [0-0f] 8d 0c 51 83 f9 14 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}