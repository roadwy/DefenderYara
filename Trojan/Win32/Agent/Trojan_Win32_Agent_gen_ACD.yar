
rule Trojan_Win32_Agent_gen_ACD{
	meta:
		description = "Trojan:Win32/Agent.gen!ACD,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {20 6c dc 0e 1c a3 db 11 8a b9 08 00 20 0c 9a 66 } //03 00 
		$a_01_1 = {55 52 4c 20 43 68 61 6e 67 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 } //02 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 6f 66 74 2e 74 72 75 73 74 69 6e 63 61 73 68 2e 63 6f 6d 2f 75 72 6c 2f 63 6f 6e 66 69 67 2e 78 6d 6c } //02 00  http://soft.trustincash.com/url/config.xml
		$a_01_3 = {43 43 68 61 6e 67 65 72 42 48 4f 20 74 72 69 65 73 20 74 6f 20 70 65 72 66 6f 72 6d 20 73 74 61 72 74 20 61 63 74 69 6f 6e 73 } //02 00  CChangerBHO tries to perform start actions
		$a_01_4 = {4c 61 73 74 43 66 67 46 65 74 63 68 } //00 00  LastCfgFetch
	condition:
		any of ($a_*)
 
}