
rule Trojan_Win32_Grandsteal_RPY_MTB{
	meta:
		description = "Trojan:Win32/Grandsteal.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 0e b8 03 00 00 00 0f b6 0d ?? ?? ?? ?? 30 4e 01 0f b6 0d ?? ?? ?? ?? 30 4e 02 0f b6 0d ?? ?? ?? ?? 30 4e 03 40 83 f8 05 74 09 8a 0d ?? ?? ?? ?? 30 0c 30 83 f8 07 75 ec a0 ?? ?? ?? ?? 02 c0 30 46 05 5e c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}