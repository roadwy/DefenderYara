
rule Trojan_Win32_Nanocore_SG_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 50 52 2e 64 6c 6c } //1 MPR.dll
		$a_01_1 = {55 00 6e 00 61 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 6f 00 70 00 65 00 6e 00 20 00 74 00 68 00 65 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 66 00 69 00 6c 00 65 00 2e 00 } //1 Unable to open the script file.
		$a_01_2 = {68 00 75 00 72 00 74 00 6c 00 69 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 hurtling.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}