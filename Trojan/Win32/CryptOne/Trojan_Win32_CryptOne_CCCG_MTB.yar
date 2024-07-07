
rule Trojan_Win32_CryptOne_CCCG_MTB{
	meta:
		description = "Trojan:Win32/CryptOne.CCCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 43 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 8b 45 f8 83 c0 90 01 01 89 45 f8 33 c0 a3 90 01 04 a1 90 01 04 83 c0 90 01 01 03 05 90 01 04 a3 90 01 04 8b 45 f8 3b 05 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}