
rule Trojan_Win64_Netwire_RA_MTB{
	meta:
		description = "Trojan:Win64/Netwire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 84 24 80 01 00 00 33 d2 48 8d 05 2c 17 03 00 48 89 44 24 20 48 8d 05 30 17 03 00 48 89 44 24 28 8d 4a 02 ff 15 a2 40 02 00 } //5
		$a_01_1 = {33 36 30 54 72 61 79 2e 65 78 65 } //1 360Tray.exe
		$a_01_2 = {73 68 65 6c 6c 63 6f 64 65 32 2e 62 69 6e } //1 shellcode2.bin
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}