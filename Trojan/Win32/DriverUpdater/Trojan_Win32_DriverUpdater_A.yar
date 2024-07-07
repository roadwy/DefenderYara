
rule Trojan_Win32_DriverUpdater_A{
	meta:
		description = "Trojan:Win32/DriverUpdater.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 4a 6f 62 52 65 6c 65 61 73 65 5c 77 69 6e 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 73 5c 78 38 36 } //1 \JobRelease\win\Release\stubs\x86
		$a_01_1 = {5b 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 46 00 6f 00 6c 00 64 00 65 00 72 00 5d 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 } //1 [AppDataFolder]System Updates\Windows Driver System Update
		$a_01_2 = {5c 00 46 00 41 00 4b 00 45 00 5f 00 44 00 49 00 52 00 5c 00 } //1 \FAKE_DIR\
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}