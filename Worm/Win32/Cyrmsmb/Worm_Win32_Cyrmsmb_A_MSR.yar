
rule Worm_Win32_Cyrmsmb_A_MSR{
	meta:
		description = "Worm:Win32/Cyrmsmb.A!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 43 79 6d 75 6c 61 74 65 57 6f 72 6d 31 5c 52 65 6c 65 61 73 65 5c 43 79 6d 75 6c 61 74 65 53 4d 42 57 6f 72 6d 2e 70 64 62 } //1 \CymulateWorm1\Release\CymulateSMBWorm.pdb
		$a_01_1 = {53 00 70 00 72 00 65 00 61 00 64 00 65 00 64 00 3a 00 74 00 72 00 75 00 65 00 20 00 25 00 6c 00 73 00 } //1 Spreaded:true %ls
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}