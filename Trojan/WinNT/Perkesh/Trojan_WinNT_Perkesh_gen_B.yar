
rule Trojan_WinNT_Perkesh_gen_B{
	meta:
		description = "Trojan:WinNT/Perkesh.gen!B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 30 00 64 00 6f 00 77 00 30 00 5c 00 53 00 79 00 30 00 74 00 65 00 6d 00 33 00 32 00 5c 00 30 00 6c 00 67 00 2e 00 65 00 78 00 65 00 } //1 wi0dow0\Sy0tem32\0lg.exe
		$a_01_1 = {50 73 31 5c 44 72 69 76 65 72 5c 69 33 38 36 5c 4b 69 6c 6c 65 72 2e 70 64 62 } //1 Ps1\Driver\i386\Killer.pdb
		$a_01_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 30 00 63 00 69 00 46 00 74 00 30 00 69 00 73 00 6b 00 } //1 \DosDevices\0ciFt0isk
		$a_01_3 = {4b 64 44 69 73 61 62 6c 65 44 65 62 75 67 67 65 72 } //1 KdDisableDebugger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}