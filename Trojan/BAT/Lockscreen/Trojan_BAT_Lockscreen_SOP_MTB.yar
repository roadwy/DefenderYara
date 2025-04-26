
rule Trojan_BAT_Lockscreen_SOP_MTB{
	meta:
		description = "Trojan:BAT/Lockscreen.SOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 13 00 00 04 6f 87 00 00 0a 1d 28 88 00 00 0a 72 ?? ?? ?? 70 28 89 00 00 0a 17 28 8a 00 00 0a 00 1d 28 88 00 00 0a 72 ?? ?? ?? 70 28 89 00 00 0a 19 73 8b 00 00 0a 80 15 00 00 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}