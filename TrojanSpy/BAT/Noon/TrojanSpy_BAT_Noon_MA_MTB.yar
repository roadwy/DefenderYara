
rule TrojanSpy_BAT_Noon_MA_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {4a 55 30 39 74 56 50 47 63 33 32 4e 57 37 } //JU09tVPGc32NW7  3
		$a_80_1 = {55 34 46 57 4c 41 74 4d 43 6a } //U4FWLAtMCj  3
		$a_80_2 = {59 6f 4d 51 32 4f 4e 55 71 68 35 50 51 56 } //YoMQ2ONUqh5PQV  3
		$a_80_3 = {58 65 6e 65 6c 6b 2e 50 72 6f 70 65 72 74 69 65 73 } //Xenelk.Properties  3
		$a_80_4 = {52 61 6e 64 6f 6d } //Random  3
		$a_80_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}