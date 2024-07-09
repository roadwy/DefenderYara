
rule Trojan_Win64_IcedID_GUS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 01 c8 44 29 d0 41 01 c0 48 8d 05 ?? ?? ?? ?? 41 29 c8 41 29 c8 45 01 c8 4d 63 c0 42 8a 04 00 32 04 32 88 04 37 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}