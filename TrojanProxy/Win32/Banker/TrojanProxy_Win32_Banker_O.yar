
rule TrojanProxy_Win32_Banker_O{
	meta:
		description = "TrojanProxy:Win32/Banker.O,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 4c 4f 49 4f 4c 41 25 73 65 74 20 70 61 69 3d 66 75 6e 63 74 69 6f 6e 20 46 69 6e 64 50 72 6f 78 79 46 0d 0a 25 4c 4f 49 4f 4c 41 25 73 65 74 20 69 78 3d 75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}