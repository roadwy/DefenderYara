
rule Trojan_BAT_AsyncRat_NEAI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 08 28 ?? 00 00 0a 7e ?? 00 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? 00 00 0a 0b de 11 de 0f } //10
		$a_01_1 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //2 WScript.Shell
		$a_01_2 = {63 00 6d 00 73 00 74 00 70 00 2e 00 65 00 78 00 65 00 } //2 cmstp.exe
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //2 powershell.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}