
rule Trojan_Win32_Qhost_DP{
	meta:
		description = "Trojan:Win32/Qhost.DP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 20 3e 3e 20 25 77 69 6e 64 69 72 25 } //3 % >> %windir%
		$a_01_1 = {61 74 74 72 69 62 20 2b 25 } //2 attrib +%
		$a_01_2 = {74 6d 70 5c 56 4b 47 75 65 73 74 2e 62 61 74 } //2 tmp\VKGuest.bat
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}