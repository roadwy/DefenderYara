
rule Trojan_Win32_CryptInject_KT{
	meta:
		description = "Trojan:Win32/CryptInject.KT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 44 45 6c 74 61 46 6f 72 6b 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 44 45 6c 74 61 46 6f 72 6b 2e 70 64 62 } //00 00  \documents\visual studio 2010\Projects\DEltaFork\x64\Release\DEltaFork.pdb
	condition:
		any of ($a_*)
 
}