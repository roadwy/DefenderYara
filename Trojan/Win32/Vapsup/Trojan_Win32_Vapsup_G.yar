
rule Trojan_Win32_Vapsup_G{
	meta:
		description = "Trojan:Win32/Vapsup.G,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //10 -LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
		$a_02_1 = {8b 45 0c 89 04 24 e8 ?? ?? ff ff [0-04] 0f b7 [0-02] 35 ?? ?? 00 00 [0-03] 89 44 24 04 8b 4d 08 89 0c 24 c7 45 ?? ?? 00 00 00 e8 ?? ?? ?? 00 8b 45 } //1
		$a_02_2 = {8b 4d 0c 89 0c 24 e8 ?? ?? ff ff [0-03] 0f b7 c0 35 ?? ?? 00 00 89 45 98 8b 02 8b 40 f4 89 45 94 8b 55 94 b8 fe ff ff 1f 29 d0 83 f8 01 72 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=11
 
}