
rule Trojan_Win64_Mikey_AS_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 74 86 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 77 86 01 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b f0 48 8d 0d 54 86 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 67 86 01 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b e8 48 8d 0d 34 86 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 57 86 01 00 48 8b c8 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}