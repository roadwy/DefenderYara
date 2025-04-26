
rule TrojanSpy_Win32_Ursnif_B_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 65 72 73 69 6f 6e 3d 25 75 26 73 6f 66 74 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 74 79 70 65 3d 25 75 26 6e 61 6d 65 3d 25 73 } //4 version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s
		$a_01_1 = {2d 00 2d 00 75 00 73 00 65 00 2d 00 73 00 70 00 64 00 79 00 3d 00 6f 00 66 00 66 00 20 00 2d 00 2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 68 00 74 00 74 00 70 00 32 00 } //1 --use-spdy=off --disable-http2
		$a_01_2 = {63 6d 64 20 2f 55 20 2f 43 20 22 74 79 70 65 20 25 73 31 20 3e 20 25 73 20 26 20 64 65 6c 20 25 73 31 22 } //1 cmd /U /C "type %s1 > %s & del %s1"
		$a_01_3 = {50 4b 31 31 5f 47 65 74 49 6e 74 65 72 6e 61 6c 4b 65 79 53 6c 6f 74 } //1 PK11_GetInternalKeySlot
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}