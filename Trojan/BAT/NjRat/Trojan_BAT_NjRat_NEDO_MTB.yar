
rule Trojan_BAT_NjRat_NEDO_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 32 33 66 66 63 35 36 2d 65 31 32 33 2d 31 32 33 34 2d 38 37 36 64 2d 31 61 33 66 31 32 33 34 35 36 65 39 } //5 123ffc56-e123-1234-876d-1a3f123456e9
		$a_01_1 = {35 35 35 35 2e 35 35 2e 33 35 36 37 2e 30 30 32 } //2 5555.55.3567.002
		$a_01_2 = {70 72 6f 63 65 73 73 2e 70 64 62 } //2 process.pdb
		$a_01_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}