
rule Backdoor_Win32_Sdbot_gen_E{
	meta:
		description = "Backdoor:Win32/Sdbot.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 53 49 5d 20 5b 53 4e 5d 3a 25 73 20 5b 43 4e 5d 3a 25 73 20 5b 55 4e 5d 3a 25 73 20 5b 4f 53 3a 5d 25 73 20 5b 43 50 55 5d } //01 00  [SI] [SN]:%s [CN]:%s [UN]:%s [OS:]%s [CPU]
		$a_01_1 = {5b 55 44 5d 20 3a 29 20 2d 3e 20 55 44 } //01 00  [UD] :) -> UD
		$a_01_2 = {5b 52 53 5d 20 3a 29 20 2d 3e 20 25 73 3a 25 64 } //01 00  [RS] :) -> %s:%d
		$a_01_3 = {5b 53 52 56 5d 3a 25 73 20 5b 65 58 65 5d 3a 25 73 20 5b 44 4c 4c 5d 3a 25 73 20 5b 4c 6f 63 61 74 69 6f 6e 5d 3a 25 73 } //01 00  [SRV]:%s [eXe]:%s [DLL]:%s [Location]:%s
		$a_01_4 = {44 44 6f 53 } //01 00  DDoS
		$a_00_5 = {64 6f 6e 65 20 77 69 74 68 20 66 6c 6f 6f 64 } //01 00  done with flood
		$a_00_6 = {25 73 3a 25 64 20 28 4c 65 6e 67 74 68 3a 25 64 20 54 68 72 65 61 64 73 3a 25 64 29 } //00 00  %s:%d (Length:%d Threads:%d)
	condition:
		any of ($a_*)
 
}