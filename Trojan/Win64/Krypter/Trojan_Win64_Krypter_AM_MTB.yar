
rule Trojan_Win64_Krypter_AM_MTB{
	meta:
		description = "Trojan:Win64/Krypter.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 e8 ?? ?? ?? ?? 48 8b cb 41 8b c7 80 31 ?? 48 ff c1 48 83 e8 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}