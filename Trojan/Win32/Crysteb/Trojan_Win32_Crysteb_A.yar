
rule Trojan_Win32_Crysteb_A{
	meta:
		description = "Trojan:Win32/Crysteb.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6d 61 74 65 72 73 2e 65 78 65 } //1 smaters.exe
		$a_01_1 = {73 76 73 6d 73 74 2e 65 78 65 } //1 svsmst.exe
		$a_01_2 = {70 65 72 66 6f 72 6d 65 72 2e 65 78 65 } //1 performer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}