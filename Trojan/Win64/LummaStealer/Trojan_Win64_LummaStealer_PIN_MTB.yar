
rule Trojan_Win64_LummaStealer_PIN_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c2 48 63 c2 48 8d 8c 24 00 01 00 00 48 03 c8 0f b6 01 43 88 04 08 44 88 11 43 0f b6 0c 08 49 03 ca 0f b6 c1 0f b6 8c 04 ?? ?? ?? ?? 30 0f 48 ff c7 49 83 eb 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}