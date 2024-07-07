
rule Trojan_Win32_Khalesi_HNS_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b 45 0c 74 0f 89 c3 83 e3 90 01 01 8a 5c 1d 90 01 01 30 1c 02 40 eb 90 00 } //2
		$a_03_1 = {0f b6 44 7e 90 01 01 c1 e3 90 01 01 89 04 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}