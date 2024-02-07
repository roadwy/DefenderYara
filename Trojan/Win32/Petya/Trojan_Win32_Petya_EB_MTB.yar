
rule Trojan_Win32_Petya_EB_MTB{
	meta:
		description = "Trojan:Win32/Petya.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 65 73 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d 20 61 6e 64 20 75 6e 69 71 75 65 20 6b 65 79 } //01 00  files have been encrypted with strongest encryption algorithm and unique key
		$a_01_1 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 49 67 6e 6f 72 65 41 6c 6c 46 61 69 6c 75 72 65 73 } //01 00  bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
		$a_81_2 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 31 20 2d 66 20 67 20 61 20 74 20 65 20 2e 20 70 20 68 20 70 20 3f } //01 00  shutdown -r -t 1 -f g a t e . p h p ?
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 57 } //01 00  SetWindowsHookExW
		$a_81_4 = {6a 20 61 20 73 20 74 20 65 20 72 20 2e 20 69 20 6e 20 2f 20 6e 20 65 20 77 20 73 20 2f } //01 00  j a s t e r . i n / n e w s /
		$a_01_5 = {52 00 75 00 6d 00 6f 00 6c 00 64 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 62 00 61 00 74 00 } //00 00  Rumold Ransomware.bat
	condition:
		any of ($a_*)
 
}