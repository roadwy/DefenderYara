
rule Trojan_Win32_Fauppod_ASGL_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.ASGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? 10 81 c2 ?? ?? ?? 00 89 15 ?? ?? ?? 10 30 c8 a2 } //5
		$a_03_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? 10 81 c2 ?? ?? ?? ff 89 15 ?? ?? ?? 10 30 c8 a2 ?? ?? ?? 10 0f b6 c0 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}