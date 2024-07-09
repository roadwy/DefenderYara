
rule TrojanProxy_Win32_Horst_U{
	meta:
		description = "TrojanProxy:Win32/Horst.U,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_02_0 = {85 c0 74 3c ff 15 ?? ?? ?? ?? c1 e8 0a 33 d2 b9 3c 00 00 00 f7 f1 50 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8b 55 08 52 e8 ?? ?? 00 00 83 c4 04 8b 4d 08 03 c8 51 ff 15 ?? ?? ?? ?? 83 c4 10 } //5
		$a_00_1 = {3f 67 65 74 5f 74 73 74 3d 36 36 36 } //2 ?get_tst=666
		$a_00_2 = {48 6f 73 74 5f 6f 74 5f 32 31 30 31 5f } //2 Host_ot_2101_
		$a_00_3 = {26 72 61 6e 64 6e 75 6d 62 61 3d 25 64 26 75 70 74 69 6d 65 3d 25 64 } //2 &randnumba=%d&uptime=%d
		$a_00_4 = {25 31 32 37 5b 30 2d 39 41 2d 5a 61 2d 7a 2e 5d } //1 %127[0-9A-Za-z.]
		$a_00_5 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 } //1 %s:*:Enabled:ipsec
		$a_00_6 = {58 2d 46 6f 72 77 61 72 64 65 64 2d 46 6f 72 3a 20 25 73 } //1 X-Forwarded-For: %s
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}