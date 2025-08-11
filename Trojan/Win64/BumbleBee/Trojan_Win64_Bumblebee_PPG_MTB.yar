
rule Trojan_Win64_Bumblebee_PPG_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 09 0b c1 88 84 24 08 b9 00 00 c7 84 24 ?? ?? ?? ?? 99 00 f1 aa 8b 84 24 9c a7 00 00 8b 8c 24 9c 9c 00 00 2b c8 8b c1 89 84 24 ?? b4 01 00 8b 84 24 c8 58 01 00 99 48 8b 8c 24 88 30 01 00 f7 39 8b 8c 24 ?? b4 01 00 3b c8 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}