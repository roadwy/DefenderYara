
rule Trojan_Win32_Fragtor_LLV_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f af c3 bb cb ff ff ff 83 f0 a7 81 f6 d4 6d 01 00 a2 ?? ?? ?? ?? 69 c1 d4 6d 01 00 29 d6 81 f6 f7 16 0a e9 09 f8 0f af c3 bb cd ff ff ff 83 f0 02 a2 ?? ?? ?? ?? 89 d0 81 e2 d8 a4 fe ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}