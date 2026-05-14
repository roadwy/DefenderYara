
rule Trojan_BAT_Heracles_VD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 71 00 00 70 02 72 75 00 00 70 28 ?? 00 00 0a 03 28 ?? 00 00 0a 2a } //5
		$a_00_1 = {78 00 78 00 78 00 78 00 2e 00 54 00 58 00 54 00 } //1 xxxx.TXT
		$a_01_2 = {54 65 6d 70 6f 72 61 72 79 20 50 72 6f 6a 65 63 74 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //1 Temporary Projects\WindowsFormsApplication1\obj\x86\Release\WindowsFormsApplication1.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}