
rule Trojan_WinNT_Perkesh_gen_A{
	meta:
		description = "Trojan:WinNT/Perkesh.gen!A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 4b 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 4d 79 52 6f 6f 74 4b 69 74 2e 70 64 62 } //1 RK\objfre\i386\MyRootKit.pdb
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 73 00 52 00 4b 00 31 00 } //1 \Device\NsRK1
		$a_01_2 = {4b 65 52 61 69 73 65 49 72 71 6c 54 6f 44 70 63 4c 65 76 65 6c } //1 KeRaiseIrqlToDpcLevel
		$a_01_3 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 } //1 ZwOpenProcess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}