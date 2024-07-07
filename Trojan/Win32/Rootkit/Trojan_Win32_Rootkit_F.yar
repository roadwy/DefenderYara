
rule Trojan_Win32_Rootkit_F{
	meta:
		description = "Trojan:Win32/Rootkit.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 50 4f 43 20 52 6f 6f 74 6b 69 74 } //1 TPOC Rootkit
		$a_03_1 = {8d 44 00 02 50 8d 85 90 01 02 ff ff 50 68 04 20 22 00 ff 35 90 01 02 40 00 90 00 } //1
		$a_03_2 = {8d 44 00 02 50 8d 85 90 01 02 ff ff 50 68 08 20 22 00 ff 35 90 01 02 40 00 ff 15 90 01 02 40 00 eb 10 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Rootkit_F_2{
	meta:
		description = "Trojan:Win32/Rootkit.F,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //10 ntoskrnl.exe
		$a_01_1 = {2e 78 64 61 74 61 } //2 .xdata
		$a_01_2 = {40 8d 48 ff 81 f9 02 01 00 00 0f 82 } //1
		$a_01_3 = {0f 85 14 00 00 00 8b 45 f4 8b 04 85 bc 42 00 10 a3 c4 42 00 10 } //1
		$a_01_4 = {8d 04 85 c8 42 00 10 01 10 41 83 f9 04 } //1
		$a_01_5 = {a1 c4 42 00 10 68 48 42 00 10 ff d0 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}