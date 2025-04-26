
rule Trojan_Win32_Redline_GBD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 3e 8b c6 83 e0 03 88 4c 24 13 53 8a 80 ?? ?? ?? ?? 32 c1 02 c1 88 04 3e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}