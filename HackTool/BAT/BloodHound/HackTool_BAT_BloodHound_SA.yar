
rule HackTool_BAT_BloodHound_SA{
	meta:
		description = "HackTool:BAT/BloodHound.SA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {42 00 6c 00 6f 00 6f 00 64 00 48 00 6f 00 75 00 6e 00 64 00 2e 00 62 00 69 00 6e 00 } //03 00  BloodHound.bin
		$a_01_1 = {63 6f 73 74 75 72 61 2e 63 6f 6d 6d 61 6e 64 6c 69 6e 65 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //03 00  costura.commandline.dll.compressed
		$a_01_2 = {63 6f 73 74 75 72 61 2e 68 65 69 6a 64 65 6e 2e 64 6e 73 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //01 00  costura.heijden.dns.dll.compressed
		$a_01_3 = {53 00 61 00 6d 00 53 00 65 00 72 00 76 00 65 00 72 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 } //01 00  SamServerExecute
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 54 65 78 74 50 77 64 41 6c 6c 6f 77 65 64 } //01 00  EncryptedTextPwdAllowed
		$a_01_5 = {67 65 74 5f 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e 53 69 64 } //01 00  get_AccountDomainSid
		$a_01_6 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 53 61 6d 41 63 63 6f 75 6e 74 4e 61 6d 65 } //01 00  get_ComputerSamAccountName
		$a_01_7 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 42 69 6e 61 72 79 46 6f 72 6d } //00 00  SetSecurityDescriptorBinaryForm
	condition:
		any of ($a_*)
 
}