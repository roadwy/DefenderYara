
rule Backdoor_Win32_Bafruz_E{
	meta:
		description = "Backdoor:Win32/Bafruz.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 74 61 74 20 2d 61 6e 6f } //1 netstat -ano
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //1 SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 6c 6f 67 69 6e 2e 76 6b 2e 63 6f 6d } //1 127.0.0.1 www.login.vk.com
		$a_01_3 = {44 6e 73 53 65 72 76 65 72 5f 31 31 } //1 DnsServer_11
		$a_01_4 = {64 6e 73 2f 73 65 6e 64 5f 70 2e 70 68 70 3f 73 69 64 3d } //1 dns/send_p.php?sid=
		$a_00_5 = {6b 6e 6f 63 6b 2e 70 68 70 3f 69 70 3d } //1 knock.php?ip=
		$a_03_6 = {ba e8 fd 00 00 b8 10 27 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 01 8d 4d } //2
		$a_03_7 = {b8 17 f6 00 00 e8 ?? ?? ?? ?? 68 88 13 00 00 e8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*2+(#a_03_7  & 1)*2) >=3
 
}