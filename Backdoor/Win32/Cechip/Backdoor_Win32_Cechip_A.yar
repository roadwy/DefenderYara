
rule Backdoor_Win32_Cechip_A{
	meta:
		description = "Backdoor:Win32/Cechip.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2d 73 73 68 20 2d 52 20 22 } //01 00  explorer.exe -ssh -R "
		$a_01_1 = {22 2b 73 65 72 76 65 72 2b 22 20 2d 6c 20 22 2b 75 73 65 72 6e 61 6d 65 2b 22 20 2d 70 77 20 22 2b 70 61 73 73 77 6f 72 64 } //01 00  "+server+" -l "+username+" -pw "+password
		$a_01_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 50 52 4f 43 45 53 53 22 29 } //01 00  .Environment("PROCESS")
		$a_01_3 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 77 69 6e 33 32 5f 70 72 6f 63 65 73 73 20 77 68 65 72 65 20 6e 61 6d 65 3d 27 65 78 70 6c 6f 72 65 72 2e 65 78 65 27 } //01 00  select * from win32_process where name='explorer.exe'
		$a_01_4 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 20 2d 64 20 2d 74 20 2d 6c 20 2d 65 30 2e 30 2e 30 2e 30 20 2d 69 31 32 37 2e 30 2e 30 2e 31 20 2d 70 } //00 00  winlogon.exe -d -t -l -e0.0.0.0 -i127.0.0.1 -p
	condition:
		any of ($a_*)
 
}