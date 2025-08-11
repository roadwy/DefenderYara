
rule Trojan_Win64_XDSpy_GVA_MTB{
	meta:
		description = "Trojan:Win64/XDSpy.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 66 66 69 63 65 75 70 64 74 63 65 6e 74 72 2e 63 6f 6d } //2 officeupdtcentr.com
		$a_01_1 = {73 65 61 74 77 6f 77 61 76 65 2e 63 6f 6d } //2 seatwowave.com
		$a_00_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 63 00 20 00 63 00 64 00 20 00 2f 00 64 00 20 00 22 00 25 00 73 00 22 00 20 00 26 00 20 00 64 00 69 00 72 00 20 00 2f 00 61 00 20 00 2f 00 2d 00 63 00 } //1 cmd.exe /u /c cd /d "%s" & dir /a /-c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}