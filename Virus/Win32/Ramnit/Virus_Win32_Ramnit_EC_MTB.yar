
rule Virus_Win32_Ramnit_EC_MTB{
	meta:
		description = "Virus:Win32/Ramnit.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 08 00 "
		
	strings :
		$a_01_0 = {32 1f 88 1f 47 4a e2 e6 68 ff 00 00 00 } //01 00 
		$a_01_1 = {4b 79 55 66 66 54 68 4f 6b 59 77 52 52 74 67 50 50 } //01 00  KyUffThOkYwRRtgPP
		$a_01_2 = {53 72 76 2e 65 78 65 } //00 00  Srv.exe
	condition:
		any of ($a_*)
 
}