
rule Trojan_Win32_Kryptik_BO_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a cb 8a 6d fd 80 f1 dd 8a 5d fe 8a 55 ff 32 6d f5 32 5d f6 32 55 f7 88 4d fc 88 6d fd 88 5d fe 88 55 ff 80 f9 e9 75 } //1
		$a_02_1 = {83 e0 03 0f b6 44 05 f4 30 82 ?? ?? ?? ?? 8b c6 83 e0 03 83 c6 05 0f b6 44 05 f4 30 82 ?? ?? ?? ?? 83 c2 05 81 fa 05 5a 00 00 72 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}