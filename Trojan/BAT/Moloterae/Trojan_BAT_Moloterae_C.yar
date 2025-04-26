
rule Trojan_BAT_Moloterae_C{
	meta:
		description = "Trojan:BAT/Moloterae.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 70 75 64 74 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 72 6f 63 65 73 73 20 48 6f 73 74 2e 70 64 62 } //1 wpudte\obj\Debug\Process Host.pdb
		$a_01_1 = {4e 00 61 00 53 00 53 00 79 00 5c 00 45 00 78 00 74 00 52 00 65 00 73 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //1 NaSSy\ExtReset.exe
		$a_01_2 = {48 6f 73 74 2e 65 78 65 00 46 6f 72 6d 31 00 77 70 75 64 74 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}