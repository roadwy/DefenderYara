
rule Trojan_Win64_Zusy_RK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 76 74 65 73 74 5c 70 72 6f 6a 65 63 74 73 5c 52 65 64 54 65 61 6d 5c 63 32 69 6d 70 6c 61 6e 74 5c 69 6d 70 6c 61 6e 74 } //1 avtest\projects\RedTeam\c2implant\implant
		$a_01_1 = {79 61 72 74 74 64 6e 2e 64 65 } //1 yarttdn.de
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 6e 61 6c 70 6d 69 2e 65 78 65 } //1 C:\ProgramData\tnalpmi.exe
		$a_01_3 = {41 00 20 00 5a 00 65 00 65 00 20 00 54 00 6f 00 6f 00 20 00 49 00 6d 00 2d 00 50 00 6c 00 61 00 6e 00 74 00 } //1 A Zee Too Im-Plant
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}