
rule Trojan_Win64_Bumblebee_WIW_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.WIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d1 0f af c2 41 8b d0 c1 ea 10 89 83 c4 00 00 00 48 63 0d ?? ?? ?? ?? 48 8b 83 98 00 00 00 88 14 01 41 8b d0 ff 05 ?? ?? 04 00 8b 43 58 2b 43 50 05 b4 d7 5c 44 c1 ea 08 31 05 ?? ?? 04 00 8b 83 c4 00 00 00 2d 58 3f 1e 00 31 43 44 48 8b 0d ?? ?? 04 00 8b 43 3c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}