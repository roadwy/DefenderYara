
rule Trojan_Win32_Staser_EN_MTB{
	meta:
		description = "Trojan:Win32/Staser.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 56 53 8b 75 14 8d 85 d8 f9 ff ff 0c 01 56 ff 15 ?? ?? ?? ?? 6a 14 6a 40 ff 15 ?? ?? ?? ?? 8b d8 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}