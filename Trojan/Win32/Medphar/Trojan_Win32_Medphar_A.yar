
rule Trojan_Win32_Medphar_A{
	meta:
		description = "Trojan:Win32/Medphar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 71 2d 70 68 61 72 6d 61 2e 6f 72 67 2f 5f 69 64 5f } //1 hq-pharma.org/_id_
		$a_01_1 = {64 72 69 76 65 72 73 5c 73 79 73 74 65 6d 2e 65 78 65 20 25 } //1 drivers\system.exe %
		$a_03_2 = {99 33 c2 2b c2 83 c0 17 8d ?? ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}