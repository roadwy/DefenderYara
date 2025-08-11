
rule Trojan_Win32_Rugmi_HG_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 89 45 ?? 8b 45 ?? 83 c0 01 50 ff 55 88 [0-ff] 0f be 11 03 55 ?? 89 55 90 1b 03 8b } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}