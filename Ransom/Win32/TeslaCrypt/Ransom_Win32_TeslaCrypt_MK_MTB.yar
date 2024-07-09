
rule Ransom_Win32_TeslaCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 34 01 00 00 35 [0-02] 00 00 8b 8c 24 14 01 00 00 c6 84 24 47 01 00 00 f3 8b 94 24 38 01 00 00 8b b4 24 3c 01 00 00 81 c2 c1 89 ff ff 83 d6 ff 89 94 24 38 01 00 00 89 b4 24 3c 01 00 00 39 c1 73 40 8b 84 24 14 01 00 00 c6 84 24 47 01 00 00 53 8b 8c 24 14 01 00 00 8a 94 04 1b 01 00 00 88 54 0c 14 8b 84 24 34 01 00 00 35 [0-02] 00 00 03 84 24 14 01 00 00 89 84 24 14 01 00 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}