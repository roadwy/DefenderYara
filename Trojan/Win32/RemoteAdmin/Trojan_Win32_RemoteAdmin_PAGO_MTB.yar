
rule Trojan_Win32_RemoteAdmin_PAGO_MTB{
	meta:
		description = "Trojan:Win32/RemoteAdmin.PAGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {3f 68 3d 72 65 6c 61 79 2e 76 61 68 65 6c 70 73 2e 74 6f 70 26 61 6d 70 3b 70 3d 38 30 34 31 26 } //5 ?h=relay.vahelps.top&amp;p=8041&
		$a_01_1 = {3f 68 3d 72 65 6c 61 79 2e 76 61 68 65 6c 70 73 2e 74 6f 70 26 61 6d 70 3b 70 3d 34 34 33 26 } //5 ?h=relay.vahelps.top&amp;p=443&
		$a_81_2 = {44 6f 74 4e 65 74 52 75 6e 6e 65 72 2e 70 64 62 } //3 DotNetRunner.pdb
		$a_81_3 = {43 6c 69 63 6b 4f 6e 63 65 52 75 6e 6e 65 72 2e 70 64 62 } //3 ClickOnceRunner.pdb
		$a_81_4 = {53 63 72 65 65 6e 43 6f 6e 6e 65 63 74 2e 43 6c 69 65 6e 74 49 6e 73 74 61 6c 6c 65 72 52 75 6e 6e 65 72 2e 70 64 62 } //1 ScreenConnect.ClientInstallerRunner.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*1) >=9
 
}