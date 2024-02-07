
rule Backdoor_Win32_Hupigon_ZAP_bit{
	meta:
		description = "Backdoor:Win32/Hupigon.ZAP!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 72 65 65 32 78 6d 6c 20 61 70 70 3d 22 53 56 43 48 4f 53 54 2e 65 78 65 } //01 00  tree2xml app="SVCHOST.exe
		$a_01_1 = {53 65 72 76 65 72 55 73 65 53 65 6c 66 44 65 66 69 6e 65 3d } //01 00  ServerUseSelfDefine=
		$a_01_2 = {43 6c 69 65 6e 74 47 72 6f 75 70 3d } //01 00  ClientGroup=
		$a_01_3 = {63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 66 20 2d 74 20 30 } //01 00  cmd /c shutdown -s -f -t 0
		$a_01_4 = {6f 62 6a 77 73 2e 52 75 6e 20 6b 61 76 70 61 74 68 } //00 00  objws.Run kavpath
	condition:
		any of ($a_*)
 
}