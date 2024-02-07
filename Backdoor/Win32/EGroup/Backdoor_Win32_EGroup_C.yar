
rule Backdoor_Win32_EGroup_C{
	meta:
		description = "Backdoor:Win32/EGroup.C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 4f 70 74 69 6f 6e 73 5c 42 52 4f 57 53 45 5c 46 52 49 45 4e 44 4c 59 5f 45 52 52 4f 52 53 } //05 00  SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\BROWSE\FRIENDLY_ERRORS
		$a_00_1 = {65 6c 65 63 74 72 6f 6e 69 63 2d 67 72 6f 75 70 } //03 00  electronic-group
		$a_00_2 = {55 4e 4c 49 4d 49 54 45 44 20 41 43 43 45 53 53 20 54 4f 20 4f 55 52 20 4e 45 54 57 4f 52 4b } //04 00  UNLIMITED ACCESS TO OUR NETWORK
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 43 6c 61 73 73 5c 7b 34 44 33 36 45 39 36 44 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d } //03 00  SYSTEM\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}
		$a_00_4 = {64 69 61 6c 20 61 20 50 52 45 4d 49 55 4d 20 52 41 54 45 20 4e 55 4d 42 45 52 } //03 00  dial a PREMIUM RATE NUMBER
		$a_01_5 = {74 68 61 74 20 79 6f 75 20 61 72 65 20 74 68 65 20 6c 69 6e 65 20 73 75 62 73 63 72 69 62 65 72 20 } //05 00  that you are the line subscriber 
		$a_01_6 = {2d 2d 49 45 41 63 63 65 73 73 } //02 00  --IEAccess
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 65 67 72 6f 75 70 } //02 00  Software\egroup
		$a_01_8 = {6e 6f 63 72 65 64 69 74 63 61 72 64 2e 63 6f 6d 2f 64 69 61 6c 2e 70 68 70 } //00 00  nocreditcard.com/dial.php
	condition:
		any of ($a_*)
 
}