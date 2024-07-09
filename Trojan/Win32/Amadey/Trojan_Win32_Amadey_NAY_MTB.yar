
rule Trojan_Win32_Amadey_NAY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ed 04 00 00 00 80 ca ?? 8b 54 25 00 33 d3 e9 b7 a4 f8 ff 0f 84 7c 61 6d 00 0f b6 11 c1 e6 ?? 66 85 ea c1 e0 08 f7 c7 ?? ?? ?? ?? 0b f2 66 ff c2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}