
rule Trojan_Win32_LummaC_MAC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 03 8b 4c 85 ?? 8a 04 18 30 04 11 b9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}