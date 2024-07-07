
rule Backdoor_Win32_Milconsd_A{
	meta:
		description = "Backdoor:Win32/Milconsd.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 6d 61 63 68 69 6e 65 20 48 61 73 20 62 65 65 6e 20 69 6e 74 6f 20 4d 69 6c 20 21 21 21 21 } //10 This machine Has been into Mil !!!!
		$a_01_1 = {53 74 61 72 74 53 6e 69 66 66 65 72 } //1 StartSniffer
		$a_01_2 = {53 74 61 72 74 55 73 62 53 74 65 61 6c } //1 StartUsbSteal
		$a_01_3 = {44 6f 77 6e 52 75 6e 20 55 52 4c 5f 31 3a } //1 DownRun URL_1:
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}