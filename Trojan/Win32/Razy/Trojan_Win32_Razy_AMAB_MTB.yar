
rule Trojan_Win32_Razy_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Razy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 0c 7d ?? 8b 45 f8 99 f7 7d f4 8b 45 f0 8a 0c 10 88 4d ff 8b 55 08 03 55 f8 0f be 02 0f be 4d ff 33 c1 8b 55 08 03 55 f8 88 02 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}