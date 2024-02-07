
rule Trojan_Win64_Cobaltstrike_EA_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 33 2e 64 6c 6c } //01 00  Dll3.dll
		$a_01_1 = {43 73 65 65 67 } //01 00  Cseeg
		$a_01_2 = {51 75 65 75 65 55 73 65 72 41 50 43 } //01 00  QueueUserAPC
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //01 00  ShellExecuteW
		$a_01_4 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 64 00 6e 00 73 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 78 00 79 00 7a 00 3a 00 32 00 30 00 38 00 37 00 } //00 00  microsoftdnsserver.xyz:2087
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_EA_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 4d 61 69 6e } //0a 00  DllMain
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {6e 73 65 66 64 77 75 61 68 70 2e 64 6c 6c } //01 00  nsefdwuahp.dll
		$a_81_3 = {61 6d 62 78 73 76 62 6f 78 72 78 72 61 74 } //01 00  ambxsvboxrxrat
		$a_81_4 = {62 76 61 79 65 74 79 7a 72 6d 6c 62 77 6c 6f } //01 00  bvayetyzrmlbwlo
		$a_81_5 = {63 73 63 75 64 62 6b 69 73 66 75 6e 73 79 } //01 00  cscudbkisfunsy
		$a_81_6 = {65 69 79 67 79 67 6d 79 6f 64 6f 61 77 66 74 74 } //00 00  eiygygmyodoawftt
	condition:
		any of ($a_*)
 
}