
rule Trojan_Win32_Malwarn{
	meta:
		description = "Trojan:Win32/Malwarn,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 61 6e 20 64 61 6d 61 64 67 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //10 can damadge your computer
		$a_00_1 = {72 65 6c 65 61 73 65 5c 4d 61 6c 77 61 72 65 4b 69 6c 6c 65 72 } //10 release\MalwareKiller
		$a_02_2 = {63 63 53 76 63 48 73 74 2e 65 78 65 90 02 04 53 68 61 72 65 61 7a 61 2e 65 78 65 90 00 } //2
		$a_00_3 = {57 41 52 4e 49 4e 47 3a 20 53 65 63 75 72 69 74 79 20 65 72 72 6f 72 21 } //2 WARNING: Security error!
		$a_00_4 = {4c 69 6d 65 57 69 72 65 2e 65 78 65 20 68 61 73 } //1 LimeWire.exe has
		$a_00_5 = {42 65 61 72 53 68 61 72 65 2e 65 78 65 20 68 61 73 } //1 BearShare.exe has
		$a_00_6 = {50 68 65 78 2e 65 78 65 20 68 61 73 } //1 Phex.exe has
		$a_00_7 = {46 72 6f 73 74 57 69 72 65 2e 65 78 65 20 68 61 73 } //1 FrostWire.exe has
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=26
 
}