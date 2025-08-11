
rule Trojan_Win64_Rugmi_HL_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 00 00 00 44 8b ?? ?? 24 8b ?? 90 1b 01 1c 90 09 07 00 48 63 48 3c 8b ?? 01 [0-ff] 44 8b [0-ff] 8b [0d 05 1d] [0-ff] ff 90 04 01 0[] } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}