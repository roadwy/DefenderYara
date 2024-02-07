
rule Trojan_Win32_Fin7_A_MTB{
	meta:
		description = "Trojan:Win32/Fin7.A!MTB!!Fin7.A!MTB,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 69 6f 6e 5f 6b 65 79 5b 69 20 25 20 65 6e 63 72 79 70 74 69 6f 6e 5f 6b 65 79 2e 6c 65 6e 67 74 68 5d 2e 63 68 61 72 43 6f 64 65 41 74 28 } //01 00  encryption_key[i % encryption_key.length].charCodeAt(
		$a_81_1 = {67 72 6f 75 70 3d 6b 73 6f 63 2e 5f 34 38 33 37 30 5f 32 39 30 31 26 72 74 3d 35 31 32 26 73 65 63 72 65 74 3d } //01 00  group=ksoc._48370_2901&rt=512&secret=
		$a_81_2 = {73 68 65 6c 6c 2e 52 75 6e 28 22 25 63 6f 6d 73 70 65 63 25 20 2f 63 20 6e 73 6c 6f 6f 6b 75 70 2e 65 78 65 20 2d 74 69 6d 65 6f 75 74 3d 35 20 2d 72 65 74 72 79 3d 33 20 2d 74 79 70 65 } //01 00  shell.Run("%comspec% /c nslookup.exe -timeout=5 -retry=3 -type
		$a_81_3 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 77 68 65 72 65 20 69 70 65 6e 61 62 6c 65 64 20 3d 20 74 72 75 65 } //01 00  select * from Win32_NetworkAdapterConfiguration where ipenabled = true
		$a_81_4 = {74 70 20 2b 20 22 20 22 20 2b 20 68 73 74 20 2b 20 22 20 22 20 2b 20 73 76 72 20 2b 20 22 20 3e 20 22 20 2b 20 6f 66 69 6c 65 } //00 00  tp + " " + hst + " " + svr + " > " + ofile
	condition:
		any of ($a_*)
 
}