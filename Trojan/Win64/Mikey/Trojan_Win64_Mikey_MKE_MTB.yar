
rule Trojan_Win64_Mikey_MKE_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 03 d1 8b ca 48 63 c9 8a 84 04 ?? ?? ?? ?? 88 84 0c ?? ?? 00 00 8b 44 24 ?? ff c0 89 44 24 } //30
		$a_01_1 = {3a 50 61 79 6c 6f 61 64 } //5 :Payload
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*5) >=35
 
}