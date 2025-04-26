
rule Worm_Win32_Kasidet_B{
	meta:
		description = "Worm:Win32/Kasidet.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 65 78 65 63 3d 31 26 74 61 73 6b 5f 69 64 3d 25 73 } //2 taskexec=1&task_id=%s
		$a_01_1 = {26 68 6f 73 74 3d 25 73 26 66 6f 72 6d 3d 25 73 26 62 72 6f 77 73 65 72 3d 25 73 } //2 &host=%s&form=%s&browser=%s
		$a_01_2 = {26 6f 73 3d 25 73 26 61 76 3d 25 73 26 6e 61 74 3d 25 73 26 } //2 &os=%s&av=%s&nat=%s&
		$a_01_3 = {4e 65 75 74 72 69 6e 6f 44 65 73 6b } //1 NeutrinoDesk
		$a_01_4 = {49 6e 6a 65 63 74 50 72 6f 63 65 64 75 72 65 20 2d 20 48 6f 6f 6b 43 68 72 6f 6d 65 } //1 InjectProcedure - HookChrome
		$a_01_5 = {74 72 61 63 6b 5f 74 79 70 65 3d 25 73 26 74 72 61 63 6b 5f 64 61 74 61 3d 25 73 26 70 72 6f 63 65 73 73 5f 6e 61 6d 65 3d 25 73 } //1 track_type=%s&track_data=%s&process_name=%s
		$a_01_6 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntiVirusProduct
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}