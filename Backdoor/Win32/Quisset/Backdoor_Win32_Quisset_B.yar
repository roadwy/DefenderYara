
rule Backdoor_Win32_Quisset_B{
	meta:
		description = "Backdoor:Win32/Quisset.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 64 53 65 61 72 63 68 2e 44 4c 4c } //2 AdSearch.DLL
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d 2f 74 72 61 63 6b 2f 63 6c 69 63 6b 2e 70 68 70 3f 64 74 73 5f 63 6f 64 65 3d } //2 http://www.ilikeclick.com/track/click.php?dts_code=
		$a_01_2 = {73 79 73 6e 6f 74 69 66 79 2e 65 78 65 } //1 sysnotify.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 63 61 73 68 62 61 63 6b 6d 6f 61 2e 63 6f 2e 6b 72 2f 72 65 77 61 72 64 2e 70 68 70 3f 6e 61 6d 65 3d 25 73 26 75 73 65 72 69 64 3d 25 73 26 6d 61 63 61 64 64 72 3d 25 73 26 6f 72 67 61 64 64 72 3d 25 73 } //3 http://cashbackmoa.co.kr/reward.php?name=%s&userid=%s&macaddr=%s&orgaddr=%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=5
 
}