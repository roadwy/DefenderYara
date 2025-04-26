
rule Trojan_Win32_Ekstak_ASGJ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 56 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 08 57 c0 e9 03 81 e1 ff 00 00 00 89 4d fc db 45 fc dc 3d } //5
		$a_03_1 = {6a 00 8d 44 24 ?? 6a 01 50 c7 44 24 ?? 0c 00 00 00 89 74 24 ?? c7 44 24 28 00 00 00 00 ff 15 ?? ?? 64 00 5f a3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}