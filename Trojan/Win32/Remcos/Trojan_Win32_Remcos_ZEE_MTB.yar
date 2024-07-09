
rule Trojan_Win32_Remcos_ZEE_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ZEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 ?? ?? ?? 8d 45 } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //1 cdn.discordapp.com
		$a_00_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4c 69 62 72 61 72 69 65 73 5c 54 45 4d 50 } //1 C:\Users\Public\Libraries\TEMP
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}