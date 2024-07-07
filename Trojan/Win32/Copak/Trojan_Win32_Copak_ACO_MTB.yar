
rule Trojan_Win32_Copak_ACO_MTB{
	meta:
		description = "Trojan:Win32/Copak.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 48 8b 5a 96 14 dd d9 8f b9 90 01 04 86 c8 67 80 11 7b af 87 75 4d 83 d9 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}