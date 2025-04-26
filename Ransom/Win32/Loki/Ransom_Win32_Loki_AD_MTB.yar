
rule Ransom_Win32_Loki_AD_MTB{
	meta:
		description = "Ransom:Win32/Loki.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 4c 6f 6b 69 } //1 SOFTWARE\Loki
		$a_81_1 = {73 63 68 74 61 73 6b 73 20 2f 43 52 45 41 54 45 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e 20 4c 6f 6b 69 20 2f 54 52 } //1 schtasks /CREATE /SC ONLOGON /TN Loki /TR
		$a_81_2 = {4c 6f 6b 69 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Loki\shell\open\command
		$a_81_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_81_4 = {77 62 61 64 6d 69 6e 20 44 45 4c 45 54 45 20 53 59 53 54 45 4d 53 54 41 54 45 42 41 43 4b 55 50 } //1 wbadmin DELETE SYSTEMSTATEBACKUP
		$a_81_5 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 wmic shadowcopy delete
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}