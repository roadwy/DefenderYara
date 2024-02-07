
rule Trojan_Win32_Paynebot_SBR_MSR{
	meta:
		description = "Trojan:Win32/Paynebot.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {36 36 2e 31 37 31 2e 32 34 38 2e 31 37 38 } //01 00  66.171.248.178
		$a_01_1 = {44 72 6f 70 70 65 64 20 62 79 20 4d 41 41 54 72 69 67 67 65 72 2d 50 61 79 6c 6f 61 64 } //01 00  Dropped by MAATrigger-Payload
		$a_01_2 = {48 6f 73 74 3a 20 62 6f 74 2e 77 68 61 74 69 73 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d } //01 00  Host: bot.whatismyipaddress.com
		$a_01_3 = {6c 6f 63 6b 65 64 20 64 6f 77 6e 20 75 73 65 72 20 77 69 74 68 20 6c 69 6d 69 74 65 64 20 4f 53 20 61 63 63 65 73 73 } //01 00  locked down user with limited OS access
		$a_01_4 = {4c 6f 63 6b 5f 70 6f 6c 69 63 79 } //00 00  Lock_policy
		$a_00_5 = {5d 04 00 00 } //30 49 
	condition:
		any of ($a_*)
 
}