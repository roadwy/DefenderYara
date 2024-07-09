
rule Trojan_Win32_Meterpreter_L{
	meta:
		description = "Trojan:Win32/Meterpreter.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e } //1
		$a_01_1 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } //1
		$a_01_2 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 } //1
		$a_01_3 = {f0 b5 a2 56 } //1
		$a_01_4 = {77 65 62 63 61 6d 5f 61 75 64 69 6f 5f 72 65 63 6f 72 64 } //1 webcam_audio_record
		$a_01_5 = {25 54 45 4d 50 25 5c 68 6f 6f 6b 2e 64 6c 6c } //1 %TEMP%\hook.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Meterpreter_L_2{
	meta:
		description = "Trojan:Win32/Meterpreter.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e } //1
		$a_01_2 = {f0 b5 a2 56 } //1
		$a_01_3 = {fe 0e 32 ea 75 } //1
		$a_01_4 = {6d 69 6d 69 6b 61 74 7a 5f 63 75 73 74 6f 6d 5f 63 6f 6d 6d 61 6e 64 } //1 mimikatz_custom_command
		$a_01_5 = {5c 00 5c 00 2e 00 5c 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 \\.\mimikatz
		$a_01_6 = {4b 00 69 00 77 00 69 00 41 00 6e 00 64 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 KiwiAndRegistryTools
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Meterpreter_L_3{
	meta:
		description = "Trojan:Win32/Meterpreter.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e } //1
		$a_01_2 = {f0 b5 a2 56 } //1
		$a_01_3 = {fe 0e 32 ea 75 } //1
		$a_01_4 = {6d 65 74 73 72 76 2e 64 6c 6c 00 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64 } //1
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 00 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 00 25 73 25 73 2e 64 6c 6c } //1
		$a_01_6 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 61 20 2f 70 3a 25 73 00 2f 74 3a 30 78 25 30 38 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}