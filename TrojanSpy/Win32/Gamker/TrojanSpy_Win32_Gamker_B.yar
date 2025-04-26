
rule TrojanSpy_Win32_Gamker_B{
	meta:
		description = "TrojanSpy:Win32/Gamker.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 64 6f 77 6e 5f 65 78 65 63 20 28 5c 53 2b 29 20 28 5c 53 2b 29 } //1 !down_exec (\S+) (\S+)
		$a_01_1 = {53 59 53 54 45 4d 21 25 73 21 } //1 SYSTEM!%s!
		$a_01_2 = {62 6f 74 69 64 3d 25 73 26 75 73 65 72 6e 61 6d 65 3d 25 73 26 76 65 72 3d 31 2e 30 26 75 70 3d 25 75 26 6f 73 3d 25 30 33 75 26 74 6f 6b 65 6e 3d 25 64 26 63 6e 3d } //1 botid=%s&username=%s&ver=1.0&up=%u&os=%03u&token=%d&cn=
		$a_01_3 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 73 65 72 76 69 63 65 20 74 79 70 65 20 3d 20 52 45 4d 4f 54 45 44 45 53 4b 54 4f 50 20 6d 6f 64 65 20 3d 20 45 4e 41 42 4c 45 } //1 netsh firewall set service type = REMOTEDESKTOP mode = ENABLE
		$a_01_4 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 :Zone.Identifier
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}