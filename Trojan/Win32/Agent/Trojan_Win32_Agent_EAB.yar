
rule Trojan_Win32_Agent_EAB{
	meta:
		description = "Trojan:Win32/Agent.EAB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 48 3c 8b 7c 01 78 03 f8 8b 77 24 8b 4f 1c 8b 57 20 8b 5f 18 03 f0 89 75 90 01 01 8b 77 14 03 c8 03 d0 89 45 90 01 01 89 4d 90 01 01 89 55 90 00 } //2
		$a_03_1 = {0f b7 40 0e 8b 4d 90 01 01 0f b7 49 0c 03 c1 39 45 90 00 } //1
		$a_00_2 = {5f 41 70 70 65 6e 64 5f 54 65 78 74 5f 56 61 6c 75 65 40 31 32 } //1 _Append_Text_Value@12
		$a_00_3 = {5f 43 6c 65 61 72 5f 44 61 74 61 54 65 78 74 40 38 } //1 _Clear_DataText@8
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}