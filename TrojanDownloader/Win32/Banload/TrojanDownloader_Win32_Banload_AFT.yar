
rule TrojanDownloader_Win32_Banload_AFT{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {54 46 69 6e 61 6c 46 61 6e 74 61 73 79 54 79 70 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 75 74 61 72 69 61 62 62 62 } //1
		$a_00_1 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 67 00 62 00 69 00 65 00 68 00 61 00 62 00 6e 00 2e 00 64 00 6c 00 6c 00 } //1 \GbPlugin\gbiehabn.dll
		$a_01_2 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73 } //1
		$a_02_3 = {00 20 00 3a 00 2e 00 2e 00 20 00 41 00 4e 00 54 00 49 00 56 00 49 00 52 00 55 00 53 00 20 00 2e 00 2e 00 3a 00 20 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 20 00 3a 00 2e 00 2e 00 56 00 45 00 52 00 53 00 41 00 4f 00 20 00 4b 00 6c 00 2e 00 2e 00 3a 00 20 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Banload_AFT_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75 } //2
		$a_00_1 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 4f 00 66 00 73 00 25 00 2e 00 38 00 58 00 25 00 2e 00 38 00 58 00 } //1 ControlOfs%.8X%.8X
		$a_00_2 = {57 00 6e 00 64 00 50 00 72 00 6f 00 63 00 50 00 74 00 72 00 25 00 2e 00 38 00 58 00 25 00 2e 00 38 00 58 00 } //1 WndProcPtr%.8X%.8X
		$a_00_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 3c 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 3e 00 } //1 System<\CurrentControlSet\Control\Keyboard Layouts\%.8>
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_Banload_AFT_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75 } //2
		$a_00_1 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //1
		$a_03_2 = {66 74 70 54 72 61 6e 73 66 65 72 [0-02] 66 74 70 52 65 61 64 79 } //1
		$a_00_3 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 4f 00 66 00 73 00 25 00 2e 00 38 00 58 00 25 00 2e 00 38 00 58 00 } //1 ControlOfs%.8X%.8X
		$a_00_4 = {6a 00 61 00 63 00 61 00 70 00 6f 00 64 00 72 00 65 00 2e 00 64 00 6f 00 6d 00 69 00 6e 00 69 00 6f 00 74 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 69 00 6f 00 2e 00 63 00 6f 00 6d 00 } //1 jacapodre.dominiotemporario.com
		$a_00_5 = {73 00 6d 00 74 00 70 00 2e 00 73 00 74 00 72 00 61 00 74 00 6f 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.strato.com
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}