
rule Trojan_Win32_Doina_AH_MTB{
	meta:
		description = "Trojan:Win32/Doina.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 61 6c 5c 54 72 61 6e 73 6d 6f 67 43 6f 61 6c 65 73 63 65 48 6f 6f 6b 5f 70 6c 61 79 65 72 } //20 Local\TransmogCoalesceHook_player
		$a_03_1 = {f6 f1 0f b6 cc 0f b6 c0 80 c9 ?? 0f b6 c9 c1 e1 ?? 8d 44 01 ?? 66 89 44 3d c2 83 c7 ?? eb } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}