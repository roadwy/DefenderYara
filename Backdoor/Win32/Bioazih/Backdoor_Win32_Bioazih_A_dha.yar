
rule Backdoor_Win32_Bioazih_A_dha{
	meta:
		description = "Backdoor:Win32/Bioazih.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_00_0 = {8a 04 31 c1 f8 04 83 e0 0f 83 f8 09 } //4
		$a_01_1 = {62 69 6f 61 7a 69 68 } //4 bioazih
		$a_01_2 = {50 61 73 73 3a 25 73 20 48 6f 73 74 6e 61 6d 65 3a 25 73 20 49 70 3a 25 73 20 4f 73 3a 25 73 20 50 72 6f 78 79 3a 25 73 20 56 6d 3a 25 73 } //2 Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s
		$a_01_3 = {2f 72 75 2f 79 79 2f 68 74 70 2e 61 73 70 } //2 /ru/yy/htp.asp
		$a_01_4 = {4c 00 4f 00 4f 00 4b 00 20 00 50 00 52 00 4f 00 20 00 46 00 49 00 4e 00 49 00 53 00 48 00 20 00 28 00 74 00 6f 00 74 00 61 00 6c 00 20 00 25 00 64 00 29 00 } //1 LOOK PRO FINISH (total %d)
		$a_01_5 = {2f 75 70 5f 6c 6f 61 64 } //1 /up_load
		$a_01_6 = {75 6e 69 73 74 61 6c } //1 unistal
		$a_01_7 = {2e 61 73 70 3f 6b 65 79 77 6f 72 64 3d } //1 .asp?keyword=
	condition:
		((#a_00_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}
rule Backdoor_Win32_Bioazih_A_dha_2{
	meta:
		description = "Backdoor:Win32/Bioazih.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 08 80 f3 04 88 1c 08 40 3b c2 7c f2 } //1
		$a_01_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 74 00 61 00 73 00 6b 00 73 00 5c 00 63 00 6f 00 6e 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\tasks\conime.exe
		$a_01_2 = {50 61 73 73 3a 25 73 20 48 6f 73 74 6e 61 6d 65 3a 25 73 20 49 70 3a 25 73 20 4f 73 3a 25 73 20 50 72 6f 78 79 3a 25 73 20 56 6d 3a 25 73 20 50 72 6f 3a } //1 Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s Pro:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}