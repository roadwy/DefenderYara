
rule Adware_Win32_Kraddare{
	meta:
		description = "Adware:Win32/Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 6d 75 75 6b 2e 63 6f 2e 6b 72 } //www.muuk.co.kr  2
		$a_80_1 = {77 69 6e 64 6f 77 73 74 61 62 2e 65 78 65 } //windowstab.exe  1
		$a_80_2 = {77 69 6e 64 6f 77 73 74 61 62 2e 70 68 70 } //windowstab.php  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}
rule Adware_Win32_Kraddare_2{
	meta:
		description = "Adware:Win32/Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 6d 75 75 6b 2e 63 6f 2e 6b 72 2f 61 70 70 2f 77 69 6e 64 6f 77 73 74 61 62 } //www.muuk.co.kr/app/windowstab  2
		$a_80_1 = {77 69 6e 64 6f 77 73 74 61 62 2e 70 68 70 } //windowstab.php  1
		$a_80_2 = {4e 65 74 58 74 72 65 6d 65 } //NetXtreme  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}
rule Adware_Win32_Kraddare_3{
	meta:
		description = "Adware:Win32/Kraddare,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 2e 66 65 65 6c 32 64 61 79 2e 63 6f 6d } //down.feel2day.com  2
		$a_80_1 = {64 6f 77 6e 2e 66 65 65 6c 32 64 61 79 2e 63 6f 6d 2f 61 70 5f 63 6e 74 2f 62 63 63 2e 70 68 70 } //down.feel2day.com/ap_cnt/bcc.php  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 46 32 44 61 79 } //Software\F2Day  1
		$a_80_3 = {66 32 64 75 78 5f 31 2e 30 2e 30 2e 32 5c 52 65 6c 65 61 73 65 5c 48 69 53 61 6e 74 61 4e 6f 74 69 66 69 65 72 2e 70 64 62 } //f2dux_1.0.0.2\Release\HiSantaNotifier.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}