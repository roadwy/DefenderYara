
rule Trojan_BAT_ReverseShell_ZJV_MTB{
	meta:
		description = "Trojan:BAT/ReverseShell.ZJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 0a 03 8d ?? 00 00 01 0b 16 0c 2b 17 00 07 08 02 08 91 7e ?? 00 00 04 08 06 5d 91 61 d2 9c 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d df 07 0d 2b 00 09 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}