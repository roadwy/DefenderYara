
rule Backdoor_Win32_Rietspoof_YA_MTB{
	meta:
		description = "Backdoor:Win32/Rietspoof.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 25 73 20 55 53 45 52 3a 20 61 64 6d 69 6e } //01 00  %s%s%s USER: admin
		$a_01_1 = {57 73 63 72 69 70 74 2e 53 6c 65 65 70 20 31 30 30 30 2a } //01 00  Wscript.Sleep 1000*
		$a_01_2 = {64 61 74 61 2e 64 61 74 } //01 00  data.dat
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 44 65 6c 65 74 65 46 69 6c 65 28 57 73 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 29 } //00 00  CreateObject("Scripting.FileSystemObject").DeleteFile(Wscript.ScriptFullName)
	condition:
		any of ($a_*)
 
}