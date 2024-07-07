
rule Trojan_Win32_Fauppod_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fa 0f b6 75 fb 89 55 f4 89 75 f0 8b 45 f4 8b 4d f0 31 c8 88 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}