
rule Ransom_Win32_Cryptolocker_MKZ_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 03 82 80 f4 00 00 8b 54 24 14 21 04 8a 8b 0b 83 eb 04 a1 ?? ?? ?? ?? 46 45 c7 04 88 23 10 00 00 a1 ?? ?? ?? ?? 0f b7 c0 3b 34 87 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}