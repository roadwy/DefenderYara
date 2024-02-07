
rule PWS_Win32_Wowsteal_gen_D{
	meta:
		description = "PWS:Win32/Wowsteal.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 30 08 01 10 8d 85 90 01 02 ff ff 6a 64 50 56 68 90 01 01 06 01 10 53 ff d7 90 00 } //02 00 
		$a_00_1 = {73 6f 66 74 79 69 6e 66 6f 72 77 6f 77 } //01 00  softyinforwow
		$a_00_2 = {25 73 3f 75 73 3d 25 73 26 70 73 3d 25 73 26 6c 76 3d 25 73 26 73 65 3d 25 73 26 71 75 3d 25 73 26 6f 73 3d 25 73 } //01 00  %s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s
		$a_00_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 73 74 61 72 74 29 } //01 00  RegSetValueEx(start)
		$a_00_4 = {2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //00 00  .worldofwarcraft.com
	condition:
		any of ($a_*)
 
}