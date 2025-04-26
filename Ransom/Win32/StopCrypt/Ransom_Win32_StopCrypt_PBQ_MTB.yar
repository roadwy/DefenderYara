
rule Ransom_Win32_StopCrypt_PBQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 05 03 4d ?? 03 c2 33 c8 8d 04 3b 33 c8 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 83 0d [0-06] 2b f1 8b ce c1 e1 04 03 4d ?? 8b c6 c1 e8 05 03 45 ?? 8d 14 33 33 ca 33 c8 2b f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}