
rule Trojan_Win64_Rugmi_HK_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 48 3c 49 ?? ?? 8b 7c ?? 2c [0-1a] ff [d0-d7] } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}