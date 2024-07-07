
rule Trojan_Win32_Zenpak_AH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {37 6b 4c 67 72 65 61 74 54 66 72 75 69 74 66 61 63 65 2e 6c 69 66 65 66 72 6f 6d } //2 7kLgreatTfruitface.lifefrom
		$a_01_1 = {49 72 26 57 4a 73 25 46 33 } //2 Ir&WJs%F3
		$a_01_2 = {33 5f 4b 49 67 37 6d 57 4e 64 74 69 79 69 68 45 76 2a 40 2f 43 2e 70 64 62 } //2 3_KIg7mWNdtiyihEv*@/C.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}