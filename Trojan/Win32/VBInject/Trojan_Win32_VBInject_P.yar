
rule Trojan_Win32_VBInject_P{
	meta:
		description = "Trojan:Win32/VBInject.P,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 50 00 30 00 69 00 73 00 30 00 6e 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 63 00 69 00 6f 00 6e 00 5c 00 52 00 65 00 64 00 45 00 64 00 69 00 74 00 69 00 6f 00 6e 00 5c 00 42 00 6c 00 61 00 63 00 6b 00 5c 00 } //01 00  C:\Users\P\Desktop\P0is0n\Programacion\RedEdition\Black\
		$a_01_1 = {70 50 72 6f 79 00 50 72 6f 6a 65 63 74 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}