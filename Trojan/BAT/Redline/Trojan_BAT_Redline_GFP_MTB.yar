
rule Trojan_BAT_Redline_GFP_MTB{
	meta:
		description = "Trojan:BAT/Redline.GFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 00 0a 38 1a 00 00 00 02 06 02 06 91 03 06 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 3f dd ff ff ff 02 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}