
rule Trojan_BAT_Redline_GMX_MTB{
	meta:
		description = "Trojan:BAT/Redline.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 04 11 02 11 04 91 02 11 04 02 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 d2 9c 20 ?? ?? ?? ?? 38 ?? ?? ?? ?? 11 06 2a } //10
		$a_03_1 = {11 03 11 04 11 02 11 04 91 02 11 04 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 20 } //10
		$a_03_2 = {11 03 11 04 11 02 11 04 91 02 11 04 02 6f ?? ?? ?? 0a 5d 28 ?? ?? ?? 06 61 d2 9c 20 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}