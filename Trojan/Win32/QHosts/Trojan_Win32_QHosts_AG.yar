
rule Trojan_Win32_QHosts_AG{
	meta:
		description = "Trojan:Win32/QHosts.AG,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {84 c0 74 4e b8 90 01 03 00 e8 90 01 03 ff 50 e8 90 01 03 ff 68 e8 03 00 00 e8 90 01 03 ff b8 90 01 03 00 90 00 } //0a 00 
		$a_02_1 = {6d 61 67 65 6e 74 73 65 74 75 70 2e 65 78 65 90 02 07 55 8b ec 33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 68 90 01 03 00 90 00 } //0a 00 
		$a_02_2 = {6d 61 67 65 6e 74 2e 65 78 65 90 02 07 55 8b ec 33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 68 90 01 03 00 90 00 } //0a 00 
		$a_00_3 = {65 78 65 2e 61 67 65 6e 74 2e 6d 61 69 6c 2e 72 75 } //0a 00  exe.agent.mail.ru
		$a_00_4 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 61 69 6c 2e 52 75 5c 41 67 65 6e 74 5c 6d 61 67 65 6e 74 2e 65 78 65 } //0a 00  :\Program Files\Mail.Ru\Agent\magent.exe
		$a_02_5 = {77 69 6e 61 6d 70 2e 65 78 65 00 90 02 10 00 6d 61 67 65 6e 74 2e 65 78 65 00 90 00 } //05 00 
		$a_00_6 = {6f 6f 2e 63 6f 6d 00 90 02 10 00 67 6c 65 2e 63 6f 6d } //05 00 
		$a_00_7 = {3a 2f 57 49 4e 44 4f 57 53 2f 73 79 73 74 65 6d 33 32 2f 64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 } //00 00  :/WINDOWS/system32/drivers/etc/hosts
	condition:
		any of ($a_*)
 
}