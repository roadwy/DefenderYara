
rule Trojan_Win32_Jaik_SX_MTB{
	meta:
		description = "Trojan:Win32/Jaik.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {84 ce c6 c6 88 5d ?? c7 45 ?? e1 cf d8 c4 c7 45 ?? cf c6 99 98 c7 45 ?? 84 ce c6 c6 88 5d ?? c7 45 ?? eb ce dc cb c7 45 ?? da c3 99 98 c7 45 ?? 84 ce c6 c6 88 5d ?? c7 45 ?? ff d9 cf d8 c7 45 ?? ef c4 dc 84 c7 45 ?? ce c6 c6 00 } //20
		$a_03_1 = {41 0f b6 d1 33 c9 83 f8 ff 0f 44 d1 89 95 ?? ?? ?? ?? 85 c0 74 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}