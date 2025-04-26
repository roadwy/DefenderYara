
rule Backdoor_WinNT_Sinowal_A{
	meta:
		description = "Backdoor:WinNT/Sinowal.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 62 4f 70 65 6e 4f 62 6a 65 63 74 42 79 4e 61 6d 65 } //1 ObOpenObjectByName
		$a_03_1 = {2e a1 34 f0 df ff 0b c0 74 ?? 8b 40 70 } //1
		$a_03_2 = {ff 45 fc 83 7d fc 25 72 ?? be 01 00 00 c0 } //1
		$a_03_3 = {8b 40 10 03 c7 eb 02 33 c0 3b c6 74 ?? ff 75 08 ff 75 ?? 57 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}