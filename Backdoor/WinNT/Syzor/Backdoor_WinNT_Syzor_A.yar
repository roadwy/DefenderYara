
rule Backdoor_WinNT_Syzor_A{
	meta:
		description = "Backdoor:WinNT/Syzor.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 6f 72 67 5c 73 79 73 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 73 79 72 69 6e 67 65 2e 70 64 62 } //1 Zorg\sys\objfre\i386\syringe.pdb
		$a_01_1 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 30 00 78 00 34 00 31 00 35 00 34 00 35 00 35 00 35 00 30 00 } //1 \BaseNamedObjects\0x41545550
		$a_01_2 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 services.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}