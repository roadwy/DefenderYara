
rule Trojan_Win32_Micropsia_A{
	meta:
		description = "Trojan:Win32/Micropsia.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 00 79 00 2d 00 66 00 69 00 6c 00 65 00 73 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 61 00 70 00 69 00 2f 00 68 00 61 00 7a 00 61 00 72 00 64 00 } //1 my-files.host/api/hazard
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntiVirusProduct
		$a_01_2 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 5c 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00 } //1 winmgmts:\\localhost\root\SecurityCenter2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}