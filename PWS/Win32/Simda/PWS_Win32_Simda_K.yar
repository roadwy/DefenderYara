
rule PWS_Win32_Simda_K{
	meta:
		description = "PWS:Win32/Simda.K,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c } //01 00  iexplore.exe|
		$a_01_1 = {62 6f 74 69 64 3d 25 73 26 76 65 72 3d } //01 00  botid=%s&ver=
		$a_01_2 = {73 6c 69 70 6b 6e 6f 74 31 } //00 00  slipknot1
	condition:
		any of ($a_*)
 
}