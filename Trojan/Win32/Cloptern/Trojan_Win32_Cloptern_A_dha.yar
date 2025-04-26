
rule Trojan_Win32_Cloptern_A_dha{
	meta:
		description = "Trojan:Win32/Cloptern.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d ec 00 74 47 6a 01 6a 00 6a 00 8d 55 } //2
		$a_01_1 = {61 69 72 70 6c 75 67 69 6e 2a 2e 64 61 74 } //1 airplugin*.dat
		$a_01_2 = {2c 73 74 61 72 74 31 20 2f 65 78 63 } //1 ,start1 /exc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}