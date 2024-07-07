
rule Trojan_Win32_Raccoon_AHB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b 45 fc f7 f1 8a 0f 32 8a d4 4e 41 00 88 0c 3e 8b 4d fc 41 47 89 4d fc 83 f9 40 72 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}