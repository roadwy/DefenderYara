
rule Trojan_Win64_Bumblebee_MPG_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 88 84 24 11 18 00 00 48 8d 05 aa cf 0b 00 48 89 84 24 e0 9b 02 00 0f be 05 53 43 02 00 48 8b 8c 24 80 60 01 00 0f be 09 d3 f8 48 8b 8c 24 c0 27 02 00 88 01 48 8b 84 24 ?? ?? ?? ?? 0f bf 00 89 84 24 a0 a0 01 00 81 bc 24 a0 a0 01 00 c2 3c 00 00 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}