
rule Trojan_BAT_Njrat_MBIF_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MBIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 64 73 66 64 73 66 73 64 64 73 66 00 61 62 64 6f 00 65 77 71 65 77 71 77 65 71 77 65 71 00 64 73 61 64 73 61 64 61 73 64 73 61 } //1
		$a_01_1 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 65 78 65 } //1 ConsoleApplication1.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}