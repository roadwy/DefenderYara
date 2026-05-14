
rule Trojan_Win32_Maloader_GMXN_MTB{
	meta:
		description = "Trojan:Win32/Maloader.GMXN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //1 msbuild.exe
		$a_00_1 = {2e 00 63 00 73 00 70 00 72 00 6f 00 6a 00 } //1 .csproj
		$a_00_2 = {2f 00 74 00 3a 00 70 00 72 00 6f 00 76 00 65 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 /t:provepowershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}