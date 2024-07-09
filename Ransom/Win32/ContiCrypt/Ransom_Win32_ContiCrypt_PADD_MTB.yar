
rule Ransom_Win32_ContiCrypt_PADD_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 08 8b 55 f0 8d 44 11 02 89 45 c0 8b 4d c0 51 8b 55 d4 52 ff 15 ?? ?? ?? ?? 8b 4d e0 89 01 8b 55 e0 83 c2 04 89 55 e0 8b 45 e8 83 c0 04 } //1
		$a_01_1 = {8b 75 98 89 55 b8 33 d0 8b 45 ac 03 45 80 33 f0 89 45 ac 8b 45 b0 c1 c6 10 03 c6 c1 c2 07 89 45 b0 33 45 80 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}