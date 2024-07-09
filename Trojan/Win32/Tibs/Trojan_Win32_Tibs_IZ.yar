
rule Trojan_Win32_Tibs_IZ{
	meta:
		description = "Trojan:Win32/Tibs.IZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 } //1 SYSTEM\CurrentControlSet\Services\SharedAccess
		$a_01_1 = {25 73 2c 20 25 64 20 25 73 20 25 30 34 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 20 25 63 25 30 32 64 25 30 32 64 } //1 %s, %d %s %04d %02d:%02d:%02d %c%02d%02d
		$a_03_2 = {6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 8b f8 83 ff ff 74 ?? ff 75 08 e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 19 66 c7 45 f0 02 00 e8 ?? ?? ?? ?? 66 89 45 f2 8b 46 0c 8b 00 8b 00 89 45 f4 6a 10 8d 45 f0 50 57 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}