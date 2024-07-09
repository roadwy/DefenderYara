
rule TrojanDropper_Win32_Small_NBV{
	meta:
		description = "TrojanDropper:Win32/Small.NBV,SIGNATURE_TYPE_PEHSTR_EXT,69 00 69 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 4c 10 40 00 53 ff 15 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 6a 05 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 } //100
		$a_00_1 = {43 3a 5c 58 2d 53 54 41 52 53 2e 65 78 65 } //5 C:\X-STARS.exe
		$a_00_2 = {63 3a 5c 6e 74 6c 63 73 2e 65 78 65 } //5 c:\ntlcs.exe
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=105
 
}