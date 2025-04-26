
rule Trojan_Win32_Ursnif_E{
	meta:
		description = "Trojan:Win32/Ursnif.E,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 68 68 75 5c 54 65 61 6d 56 69 65 77 65 72 5f 31 33 2e 62 6a 62 6a 5c 42 75 69 6c 64 54 61 72 67 65 74 5c 52 65 6c 65 61 73 65 32 30 31 37 5c 74 76 5f 77 33 32 64 6c 6c 2e 70 64 62 } //1 E:\hhu\TeamViewer_13.bjbj\BuildTarget\Release2017\tv_w32dll.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}