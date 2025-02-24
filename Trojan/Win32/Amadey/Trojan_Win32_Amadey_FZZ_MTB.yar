
rule Trojan_Win32_Amadey_FZZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.FZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 0f 84 20 00 00 00 8b 85 05 17 2d 12 bb 00 00 00 00 0b db 0f 85 ?? ?? ?? ?? 28 24 39 30 04 39 49 0f 85 ?? ?? ?? ?? 61 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}