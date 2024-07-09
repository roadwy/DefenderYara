
rule Trojan_Win32_Redline_GCP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 3c 2e 8b c6 83 e0 03 68 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 2a df 00 1c 2e 46 59 3b f7 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}