
rule Trojan_BAT_Qhost_ARA_MTB{
	meta:
		description = "Trojan:BAT/Qhost.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 36 65 33 65 39 38 39 64 2d 31 30 61 34 2d 34 38 36 32 2d 61 30 38 61 2d 62 30 32 36 66 37 61 31 35 63 32 30 7d } //2 {6e3e989d-10a4-4862-a08a-b026f7a15c20}
		$a_01_1 = {4d 79 46 69 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 MyFile.Resources.resources
		$a_00_2 = {43 00 6f 00 70 00 79 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 54 00 6f 00 6f 00 6c 00 53 00 74 00 72 00 69 00 70 00 4d 00 65 00 6e 00 75 00 49 00 74 00 65 00 6d 00 2e 00 49 00 6d 00 61 00 67 00 65 00 } //2 CopyPasswordToolStripMenuItem.Image
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}