
rule Trojan_BAT_Bladabindi_NQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 36 37 2e 37 31 2e 31 34 2e 31 33 35 } //2 http://167.71.14.135
		$a_81_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 } //1 Add-MpPreference -ExclusionProcess
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 powershell.exe
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 2e 65 78 65 } //1 Microsoft\Windows\Windows.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}