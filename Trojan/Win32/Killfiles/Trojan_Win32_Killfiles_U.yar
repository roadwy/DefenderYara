
rule Trojan_Win32_Killfiles_U{
	meta:
		description = "Trojan:Win32/Killfiles.U,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {eb 09 8b 45 b4 83 c0 01 89 45 b4 83 7d b4 1b 7d 10 8b 4d b4 8b 55 08 c7 44 8a 38 ?? ?? ?? 00 } //10
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 31 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 67 00 62 00 69 00 65 00 68 00 } //1 \Device\HarddiskVolume1\WINDOWS\Downloaded Program Files\gbieh
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 31 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //1 \Device\HarddiskVolume1\Arquivos de Programas\GbPlugin\
		$a_02_3 = {64 3a 5c 70 72 6f 67 73 5c 67 62 7a 69 6e 68 6f 5c 6f 62 6a 63 68 6b [0-0a] 5c 69 33 38 36 5c 44 72 69 76 65 72 2e 70 64 62 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=12
 
}