
rule Trojan_Win32_Injector_AHB_MTB{
	meta:
		description = "Trojan:Win32/Injector.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 b8 03 45 a8 2d ?? ?? ?? ?? 2b c7 03 45 9c 31 03 83 c6 ?? 83 c3 ?? 3b 75 d0 72 } //30
		$a_03_1 = {03 45 d4 2b c2 83 c0 ?? 89 45 ec ff 75 fc b9 ?? ?? ?? ?? ff 75 f8 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}