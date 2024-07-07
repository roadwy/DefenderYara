
rule Backdoor_Win32_Androm_AO_MTB{
	meta:
		description = "Backdoor:Win32/Androm.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 12 00 fc 95 12 00 10 96 12 00 20 96 12 00 32 96 12 00 46 96 12 00 5a 96 12 00 66 96 12 00 76 } //2
		$a_01_1 = {63 00 3a 00 5c 00 70 00 61 00 72 00 63 00 68 00 65 00 5c 00 74 00 69 00 63 00 74 00 61 00 63 00 2e 00 65 00 78 00 65 00 } //2 c:\parche\tictac.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}