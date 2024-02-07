
rule Trojan_Win32_TrickBot_J_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.J!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 59 58 45 51 58 38 64 4d 59 57 4b 67 58 38 4b 4d 4e 51 70 71 43 4c } //01 00  XYXEQX8dMYWKgX8KMNQpqCL
		$a_01_1 = {67 4d 6f 66 48 2e 64 6c 6c } //01 00  gMofH.dll
		$a_01_2 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00 } //00 00 
		$a_01_3 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}