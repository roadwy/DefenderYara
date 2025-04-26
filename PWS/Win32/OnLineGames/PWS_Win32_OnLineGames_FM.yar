
rule PWS_Win32_OnLineGames_FM{
	meta:
		description = "PWS:Win32/OnLineGames.FM,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 "
		
	strings :
		$a_02_0 = {33 d2 6a 0d 8b c1 5b f7 f3 8d bc 0d 30 f9 ff ff 8a 82 ?? ?? ?? ?? 8b 55 0c 32 04 0a 32 07 32 c1 41 3b ce 88 07 7c ?? 8b 7d 08 33 db 53 53 53 ff 37 ff 15 } //10
		$a_00_1 = {77 00 73 00 63 00 6e 00 74 00 66 00 79 00 5f 00 6d 00 74 00 78 00 } //10 wscntfy_mtx
		$a_00_2 = {26 6d 6f 72 70 68 5f 69 64 3d } //10 &morph_id=
		$a_02_3 = {6d 72 74 2e 65 78 65 [0-04] 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c [0-08] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1) >=30
 
}