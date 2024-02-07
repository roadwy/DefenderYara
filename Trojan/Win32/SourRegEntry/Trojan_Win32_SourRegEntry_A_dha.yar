
rule Trojan_Win32_SourRegEntry_A_dha{
	meta:
		description = "Trojan:Win32/SourRegEntry.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 72 65 67 65 6e 74 72 79 2e 70 64 62 } //02 00  \regentry.pdb
		$a_01_1 = {6d 73 71 72 76 63 2e 65 78 65 } //01 00  msqrvc.exe
		$a_01_2 = {43 3a 5c 4c 49 43 45 4e 53 45 2e 54 58 54 } //01 00  C:\LICENSE.TXT
		$a_01_3 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 2a } //01 00  C:\Documents and Settings\*
		$a_01_4 = {5c 53 79 73 74 65 6d 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //00 00  \SystemVolumeInformation.txt
	condition:
		any of ($a_*)
 
}