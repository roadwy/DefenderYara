
rule Trojan_Win32_Tibs_gen_N{
	meta:
		description = "Trojan:Win32/Tibs.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_1 = {2e 70 68 70 3f 61 66 66 69 64 3d 25 75 } //1 .php?affid=%u
		$a_01_2 = {25 73 25 73 25 73 74 69 62 73 2e 6a 70 67 } //1 %s%s%stibs.jpg
		$a_01_3 = {3f 61 66 66 69 64 3d 25 75 26 63 6f 64 65 31 3d 25 63 25 63 25 63 25 63 } //1 ?affid=%u&code1=%c%c%c%c
		$a_01_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 27 25 73 27 } //1 netsh firewall set allowedprogram '%s'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}