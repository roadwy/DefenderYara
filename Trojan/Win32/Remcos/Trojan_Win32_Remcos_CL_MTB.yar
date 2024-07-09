
rule Trojan_Win32_Remcos_CL_MTB{
	meta:
		description = "Trojan:Win32/Remcos.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 3b 45 10 ?? ?? 8b 4d f8 03 4d fc 8b 55 f4 03 55 fc 8a 02 88 01 eb } //10
		$a_81_1 = {74 61 6d 61 67 6f 63 68 69 } //1 tamagochi
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}