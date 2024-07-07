
rule Backdoor_Win32_Webdialer{
	meta:
		description = "Backdoor:Win32/Webdialer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 63 66 6d 3f 74 69 64 3d 26 63 6e 5f 69 64 3d } //1 .cfm?tid=&cn_id=
		$a_00_1 = {4f 70 65 6e 69 6e 67 20 74 68 65 20 70 6f 72 74 2e 2e 2e } //1 Opening the port...
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 57 65 62 64 69 61 6c 65 72 } //1 Software\Webdialer
		$a_01_3 = {50 52 45 4d 49 55 4d 20 4c 4f 4e 47 20 44 49 53 54 41 4e 43 45 20 54 4f 4c 4c } //1 PREMIUM LONG DISTANCE TOLL
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 41 75 74 6f 43 6f 6e 6e 65 63 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}