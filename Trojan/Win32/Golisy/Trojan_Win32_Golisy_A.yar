
rule Trojan_Win32_Golisy_A{
	meta:
		description = "Trojan:Win32/Golisy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2e 70 68 70 3f 70 61 67 65 3d 63 70 61 6e 65 6c 26 73 75 62 3d 67 65 74 26 69 64 3d } //.php?page=cpanel&sub=get&id=  1
		$a_03_1 = {33 c9 8a 88 99 01 00 00 51 8b 55 90 01 01 33 c0 8a 82 98 01 00 00 50 8b 4d 90 1b 00 33 d2 8a 91 97 01 00 00 52 8b 45 90 1b 00 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}