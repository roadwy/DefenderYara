
rule Trojan_Win32_Fauppod_AMAF_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 0b 8b 55 e8 8b 75 d0 8a 2c 32 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 cd 8b 55 e4 88 2c 32 8b 55 f0 39 d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}