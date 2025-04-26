
rule Trojan_Win32_Fauppod_PPHH_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PPHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 50 8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? 0f b6 55 fb 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}