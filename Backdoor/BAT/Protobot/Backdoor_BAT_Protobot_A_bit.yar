
rule Backdoor_BAT_Protobot_A_bit{
	meta:
		description = "Backdoor:BAT/Protobot.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 61 00 71 00 65 00 62 00 6f 00 6f 00 6b 00 2e 00 62 00 6c 00 6f 00 67 00 73 00 70 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 74 00 72 00 } //01 00  faqebook.blogspot.com.tr
		$a_01_1 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 73 00 5c 00 73 00 79 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  C:\Temps\sys.exe
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {77 00 69 00 6e 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  winsearch.Resources
	condition:
		any of ($a_*)
 
}