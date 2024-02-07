
rule Trojan_Win32_Trickbot_SJ_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SJ!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 00 53 00 65 00 6c 00 66 00 20 00 44 00 65 00 73 00 74 00 72 00 75 00 63 00 74 00 } //01 00  &Self Destruct
		$a_01_1 = {26 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //01 00  &Execute Remote Program
		$a_01_2 = {73 00 65 00 63 00 72 00 65 00 74 00 5f 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 20 00 4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  secret_controller MFC Application
	condition:
		any of ($a_*)
 
}