
rule Ransom_Win32_ContiPacker_MTB{
	meta:
		description = "Ransom:Win32/ContiPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 46 01 0f b6 f0 8d 8d ?? ?? ?? ?? 89 b5 ?? ?? ?? ?? 0f b6 04 31 03 c2 0f b6 d0 8b c1 03 c2 89 95 ?? ?? ?? ?? 8a 1c 31 88 9d ?? ?? ?? ?? 3a 18 8b 9d ?? ?? ?? ?? 74 ?? 8a 10 88 14 31 8a 8d ?? ?? ?? ?? 88 08 8b 95 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? ?? 03 c8 0f b6 c1 8a 8c 05 ?? ?? ?? ?? 8d 04 1f 30 08 47 3b bd ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}