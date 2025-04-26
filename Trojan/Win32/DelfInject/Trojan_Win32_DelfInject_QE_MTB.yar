
rule Trojan_Win32_DelfInject_QE_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 4c 00 5f 00 4d 00 50 00 42 00 41 00 43 00 4b } //3
		$a_01_1 = {44 00 49 00 5f 00 4d 00 50 00 52 00 45 00 43 00 4f 00 52 00 44 } //3
		$a_81_2 = {41 70 69 53 65 74 48 6f 73 74 2e 41 70 70 45 78 65 63 75 74 69 6f 6e 41 6c 69 61 73 } //3 ApiSetHost.AppExecutionAlias
		$a_01_3 = {38 38 38 45 50 50 50 66 51 51 51 66 51 51 51 66 53 56 57 66 54 57 58 66 54 57 58 66 55 58 59 66 54 56 57 66 54 56 57 66 51 52 52 66 51 51 51 66 50 50 50 66 38 38 38 45 } //3 888EPPPfQQQfQQQfSVWfTWXfTWXfUXYfTVWfTVWfQRRfQQQfPPPf888E
		$a_81_4 = {57 69 6e 53 70 6f 6f 6c } //3 WinSpool
		$a_81_5 = {49 6e 65 74 49 73 4f 66 66 6c 69 6e 65 } //3 InetIsOffline
		$a_81_6 = {54 72 61 63 6b 4d 6f 75 73 65 45 76 65 6e 74 } //3 TrackMouseEvent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_81_2  & 1)*3+(#a_01_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}