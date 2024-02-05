
rule Ransom_Win32_Zudochka_AR_MTB{
	meta:
		description = "Ransom:Win32/Zudochka.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {2e 62 61 63 6b 75 70 64 62 } //.backupdb  01 00 
		$a_80_1 = {5c 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c } //\System Volume Information\  02 00 
		$a_80_2 = {25 73 5c 52 65 61 64 6d 65 2e 52 45 41 44 4d 45 } //%s\Readme.README  02 00 
		$a_80_3 = {6e 2e 6c 6f 63 6b 65 64 } //n.locked  02 00 
		$a_80_4 = {54 6f 20 67 65 74 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 62 61 63 6b 20 63 6f 6e 74 61 63 74 20 75 73 3a } //To get all your data back contact us:  02 00 
		$a_80_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 72 6f 6f 74 5c 73 79 73 74 65 6d 5c 2a 2e 2a } //C:\WINDOWS\SYSTEM32\drivers\root\system\*.*  02 00 
		$a_80_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 67 6d 72 65 61 64 6d 65 2e 74 78 74 } //C:\WINDOWS\SYSTEM32\drivers\gmreadme.txt  00 00 
		$a_00_7 = {5d 04 00 00 5c 2a } //04 80 
	condition:
		any of ($a_*)
 
}