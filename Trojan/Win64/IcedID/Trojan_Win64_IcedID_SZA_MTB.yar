
rule Trojan_Win64_IcedID_SZA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 66 ?? ?? 74 ?? 48 ?? ?? b9 ?? ?? ?? ?? 48 ?? ?? 3a c9 74 90 0a 2f 00 3a c0 74 ?? 89 44 24 ?? 48 ?? ?? ?? ?? 33 d2 66 ?? ?? 74 ?? 8b 4c 24 } //1
		$a_00_1 = {49 6e 69 74 } //1 Init
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}