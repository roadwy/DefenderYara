
rule Worm_Win32_Zazorex_C{
	meta:
		description = "Worm:Win32/Zazorex.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 76 61 6c 75 65 20 20 46 52 4f 4d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 20 57 48 45 52 45 20 6e 61 6d 65 20 3d 20 27 25 73 27 20 4f 52 44 45 52 20 42 59 20 6e 61 6d 65 3b } //1 SELECT value  FROM moz_cookies WHERE name = '%s' ORDER BY name;
		$a_01_1 = {26 74 6f 5f 6f 66 66 6c 69 6e 65 3d 66 61 6c 73 65 26 74 6f 5f 69 64 6c 65 3d 66 61 6c 73 65 26 70 6f 73 74 5f 66 6f 72 6d 5f 69 64 3d 25 73 26 66 62 5f 64 74 73 67 3d 25 73 26 6c 73 64 26 70 6f 73 74 5f 66 6f 72 6d 5f 69 64 5f 73 6f 75 72 63 65 3d 41 73 79 6e 63 52 65 71 75 65 73 74 } //1 &to_offline=false&to_idle=false&post_form_id=%s&fb_dtsg=%s&lsd&post_form_id_source=AsyncRequest
		$a_01_2 = {2f 61 6a 61 78 2f 63 68 61 74 2f 62 75 64 64 79 5f 6c 69 73 74 2e 70 68 70 3f 5f 5f 61 3d 31 } //1 /ajax/chat/buddy_list.php?__a=1
		$a_01_3 = {2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70 3f 5f 5f 61 3d 31 } //1 /ajax/chat/send.php?__a=1
		$a_01_4 = {63 61 70 74 63 68 61 } //1 captcha
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}