
rule Backdoor_Win32_Smadow_gen_B{
	meta:
		description = "Backdoor:Win32/Smadow.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 5d 04 00 00 eb ?? 53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ff ff 8b d8 85 db 75 ?? ff 76 78 e8 ?? ?? 00 00 6a 08 58 eb } //2
		$a_03_1 = {3d 64 69 73 63 0f 84 ?? ?? 00 00 3d 73 65 6e 64 0f 84 ?? ?? 00 00 3d 63 6e 63 74 74 ?? 3d 72 65 63 76 74 ?? cc e9 } //2
		$a_01_2 = {c7 00 2e 63 6e 00 } //1
		$a_00_3 = {47 45 54 20 2f 64 6c 6c 2f 25 75 2e 64 6c 6c 20 48 54 54 50 2f 31 2e 31 } //1 GET /dll/%u.dll HTTP/1.1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}