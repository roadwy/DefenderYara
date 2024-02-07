
rule Backdoor_Win32_Mdmbot_H_dll{
	meta:
		description = "Backdoor:Win32/Mdmbot.H!dll!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 61 00 63 00 68 00 65 00 2e 00 64 00 6e 00 73 00 64 00 65 00 2e 00 63 00 6f 00 6d 00 } //01 00  cache.dnsde.com
		$a_00_1 = {5f 00 5f 00 72 00 61 00 74 00 5f 00 55 00 6e 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 5f 00 25 00 64 00 } //01 00  __rat_UnInstall__%d
		$a_10_2 = {4e 65 76 65 72 53 61 79 44 69 65 21 } //01 00  NeverSayDie!
		$a_00_3 = {25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 5f 00 70 00 2e 00 61 00 78 00 } //01 00  %%TEMP%%\%s_p.ax
		$a_00_4 = {68 74 74 70 3a 2f 2f 25 6c 73 3a 25 64 2f 6c 25 78 } //00 00  http://%ls:%d/l%x
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}