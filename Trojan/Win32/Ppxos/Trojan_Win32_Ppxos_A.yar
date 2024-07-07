
rule Trojan_Win32_Ppxos_A{
	meta:
		description = "Trojan:Win32/Ppxos.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 79 50 72 6f 6a 5c 50 50 50 72 6f 6a 5c 52 65 6c 65 61 73 65 5c 50 50 43 6c 69 65 6e 74 2e 70 64 62 } //1 \MyProj\PPProj\Release\PPClient.pdb
		$a_01_1 = {2a 5c 73 68 65 6c 6c 5c 73 61 6e 64 62 6f 78 } //1 *\shell\sandbox
		$a_01_2 = {25 73 65 78 25 73 72 } //1 %sex%sr
		$a_01_3 = {2f 74 6a 2e 70 68 70 3f 69 64 3d 25 64 } //1 /tj.php?id=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}