
rule Ransom_Win32_ContiPacker_MTB{
	meta:
		description = "Ransom:Win32/ContiPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 46 01 0f b6 f0 8d 8d 90 01 04 89 b5 90 01 04 0f b6 04 31 03 c2 0f b6 d0 8b c1 03 c2 89 95 90 01 04 8a 1c 31 88 9d 90 01 04 3a 18 8b 9d 90 01 04 74 90 01 01 8a 10 88 14 31 8a 8d 90 01 04 88 08 8b 95 90 01 04 8b b5 90 01 04 0f b6 90 01 06 0f b6 90 01 06 03 c8 0f b6 c1 8a 8c 05 90 01 04 8d 04 1f 30 08 47 3b bd 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}