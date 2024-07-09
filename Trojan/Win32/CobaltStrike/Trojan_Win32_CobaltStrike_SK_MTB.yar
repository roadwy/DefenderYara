
rule Trojan_Win32_CobaltStrike_SK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 31 46 48 8b 46 ?? 83 f0 ?? 01 46 ?? 8b 46 ?? 2d ?? ?? ?? ?? 31 86 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 46 ?? 01 86 ?? ?? ?? ?? 8b 8e ?? ?? ?? ?? 8b 46 } //1
		$a_00_1 = {52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 RegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_CobaltStrike_SK_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.SK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 46 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 54 65 6e 63 65 6e 74 69 64 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 4d 4f 20 31 20 2f 54 52 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 74 65 6e 63 65 6e 74 73 6f 73 6f 2e 65 78 65 } //1 /F /Create /TN Tencentid /sc minute /MO 1 /TR C:\Users\Public\Music\tencentsoso.exe
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 63 69 61 2e 70 6c 61 6e } //5 C:\Users\Public\Music\cia.plan
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 53 69 64 65 42 61 72 2e 64 6c 6c } //1 C:\Users\Public\Music\SideBar.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=7
 
}