
rule Trojan_Win32_Doina_RPX_MTB{
	meta:
		description = "Trojan:Win32/Doina.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff ff ff 10 6a 40 68 00 10 00 00 68 90 01 03 00 6a 00 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Doina_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Doina.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 00 65 00 77 00 65 00 62 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1 iewebbc.exe
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /f /im
		$a_01_2 = {50 00 6c 00 61 00 6e 00 53 00 68 00 65 00 6c 00 6c 00 } //1 PlanShell
		$a_01_3 = {57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 Wscript.shell
		$a_01_4 = {2a 00 2e 00 6c 00 6e 00 6b 00 2a 00 } //1 *.lnk*
		$a_01_5 = {32 00 33 00 34 00 35 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 6b 00 61 00 62 00 63 00 64 00 65 00 } //1 2345.com/?kabcde
		$a_01_6 = {32 00 33 00 34 00 35 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 2345Explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}