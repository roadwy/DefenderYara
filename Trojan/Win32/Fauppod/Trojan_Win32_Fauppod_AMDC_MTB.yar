
rule Trojan_Win32_Fauppod_AMDC_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AMDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 0c 8a 4d 08 31 d2 88 d4 [0-1e] 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 [0-15] 0f b6 c4 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}