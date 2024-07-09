
rule Trojan_Win32_Redline_NC_MTB{
	meta:
		description = "Trojan:Win32/Redline.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 86 c8 61 ff 4d ?? 8b 45 ?? 0f 85 ?? ?? ?? ?? 90 0a 41 00 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 33 c8 89 4d ?? 8b 45 ?? 29 45 ?? 81 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}