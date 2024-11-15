
rule Trojan_Win64_MeduzaStealer_SIN_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.SIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 49 f7 e0 48 c1 ea 03 48 8d 04 92 48 89 ca 48 01 c0 48 29 c2 0f b6 84 14 ?? ?? ?? ?? 30 04 0b 48 83 c1 01 48 81 f9 00 1a 13 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}