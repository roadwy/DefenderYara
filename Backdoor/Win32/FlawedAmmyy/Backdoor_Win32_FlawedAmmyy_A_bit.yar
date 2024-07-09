
rule Backdoor_Win32_FlawedAmmyy_A_bit{
	meta:
		description = "Backdoor:Win32/FlawedAmmyy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 76 63 68 c7 45 ?? 6f 73 74 2e c7 45 ?? 65 78 65 00 } //1
		$a_00_1 = {25 73 5c 41 4d 4d 59 59 5c 77 6d 69 68 6f 73 74 2e 65 78 65 } //1 %s\AMMYY\wmihost.exe
		$a_00_2 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 20 48 65 6c 70 5c 77 73 75 73 2e 65 78 65 } //1 %s\Microsoft Help\wsus.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}