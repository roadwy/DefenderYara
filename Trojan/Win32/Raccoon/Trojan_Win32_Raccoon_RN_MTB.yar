
rule Trojan_Win32_Raccoon_RN_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 34 af 03 f0 45 53 51 b9 4d 6f 61 64 83 e9 02 8b d9 59 83 c3 01 39 1e 5b 75 e5 53 60 0a ed 66 83 d8 2a 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RN_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 [0-25] 55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}