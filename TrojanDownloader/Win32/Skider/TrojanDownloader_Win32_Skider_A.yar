
rule TrojanDownloader_Win32_Skider_A{
	meta:
		description = "TrojanDownloader:Win32/Skider.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {c7 44 24 14 01 00 00 00 c6 44 24 13 00 e8 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 8d 4c 24 08 50 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 8b b4 24 ?? ?? 00 00 8d 4c 24 08 56 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 8d 4c 24 14 e8 ?? ?? 00 00 8d 4c 24 2c } //1
		$a_00_1 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 64 69 73 6b 73 74 65 72 2e 63 6f 6d 2f 44 42 2f } //1 http://update.diskster.com/DB/
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 69 73 6b 73 74 65 72 5c 44 61 74 61 5c } //1 C:\Program Files\Diskster\Data\
		$a_00_3 = {44 69 73 6b 31 30 30 34 2e 69 63 6f } //1 Disk1004.ico
		$a_00_4 = {64 69 73 6b 31 30 30 34 2e 69 6e 69 } //1 disk1004.ini
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}