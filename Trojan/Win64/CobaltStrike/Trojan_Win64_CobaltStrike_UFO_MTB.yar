
rule Trojan_Win64_CobaltStrike_UFO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.UFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 48 63 ca 8a 04 0c 42 88 04 1c 44 88 14 0c 42 0f b6 04 1c 49 03 c2 0f b6 c0 8a 0c 04 30 0b 48 ff c3 49 83 e8 01 75 a8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}