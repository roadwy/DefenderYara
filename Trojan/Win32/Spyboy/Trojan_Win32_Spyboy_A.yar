
rule Trojan_Win32_Spyboy_A{
	meta:
		description = "Trojan:Win32/Spyboy.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 63 72 2d 70 72 6f 74 65 63 74 2e 63 79 62 65 72 65 61 73 6f 6e 2e 6e 65 74 } //https://cr-protect.cybereason.net  1
		$a_80_1 = {4c 68 39 71 65 6c 6c 41 44 79 47 42 59 62 73 4e 55 34 44 6f 71 56 58 38 45 31 34 3d } //Lh9qellADyGBYbsNU4DoqVX8E14=  1
		$a_80_2 = {67 6f 3a 62 75 69 6c 64 69 64 } //go:buildid  1
		$a_80_3 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 } //TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAA  1
		$a_80_4 = {48 89 44 24 58 48 89 5c 24 48 48 8b 4c 24 50 48 8b 7c 24 38 48 8b 74 24 40 41 b8 a4 01 00 00 e8 } //H�D$XH�\$HH�L$PH�|$8H�t$@A��  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}