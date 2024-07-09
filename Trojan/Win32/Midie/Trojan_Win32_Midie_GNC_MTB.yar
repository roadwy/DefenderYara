
rule Trojan_Win32_Midie_GNC_MTB{
	meta:
		description = "Trojan:Win32/Midie.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 41 fd c0 c8 03 32 82 ?? ?? ?? ?? 88 41 fd 8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 ?? ?? ?? ?? 88 41 fe 8d 42 01 99 f7 ff 83 ee } //10
		$a_01_1 = {48 76 44 65 63 6c 59 } //1 HvDeclY
		$a_01_2 = {5f 46 69 6c 65 45 78 63 69 73 74 73 40 34 } //1 _FileExcists@4
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}