
rule Trojan_BAT_Convagent_MKC_MTB{
	meta:
		description = "Trojan:BAT/Convagent.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 6f 14 00 00 0a 28 15 00 00 0a 6f 16 00 00 0a 28 17 00 00 0a 28 02 00 00 06 } //20
		$a_81_1 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 54 4e 20 27 50 72 6f 67 72 61 6d 73 55 70 64 61 74 65 5c 55 70 64 61 74 65 53 65 63 75 72 69 74 79 27 } //10 schtasks.exe /create /TN 'ProgramsUpdate\UpdateSecurity'
		$a_81_2 = {2f 53 43 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 34 20 2f 74 72 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4c 69 62 72 61 72 69 65 73 5c 6c 69 62 75 70 64 61 74 65 2e 63 6f 6d 20 2f 66 3b } //5 /SC minute /mo 4 /tr C:\Users\Public\Libraries\libupdate.com /f;
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}