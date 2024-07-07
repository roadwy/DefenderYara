
rule Trojan_Win32_Agent_RX{
	meta:
		description = "Trojan:Win32/Agent.RX,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 04 00 00 "
		
	strings :
		$a_00_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6e 74 6f 73 6b 72 6e 6c 2e 64 6c 6c 20 2c 20 44 6c 6c 4d 61 69 6e } //100 rundll32.exe C:\WINDOWS\SYSTEM32\ntoskrnl.dll , DllMain
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 69 6e 65 74 78 90 01 03 2e 69 6d 67 90 00 } //100
		$a_00_2 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //100 winsta0\default
		$a_00_3 = {4f 46 54 57 41 52 45 5c 4d 69 63 1d f6 2f 6f 35 73 6f 66 57 69 6e 64 6f 77 73 4f 56 eb b6 cd df 2f 69 6f 6e 5c 52 75 6e 5c 64 48 76 11 5c 0b 36 b0 ff db 1c 73 79 73 74 65 6d 2e 65 78 65 1b 40 b1 f2 dd b7 7c 78 2a 2e 2a 23 73 76 63 68 6f 21 fd b7 d6 66 a7 13 36 11 6b 72 6e 6c 2e 64 6c 6c } //100
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100) >=300
 
}