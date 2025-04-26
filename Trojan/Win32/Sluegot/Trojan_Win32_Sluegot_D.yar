
rule Trojan_Win32_Sluegot_D{
	meta:
		description = "Trojan:Win32/Sluegot.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 72 75 6e 66 69 6c 65 00 } //1
		$a_01_1 = {00 6b 69 6c 6c 70 00 } //1
		$a_01_2 = {00 72 65 73 68 65 6c 6c 00 } //1
		$a_01_3 = {00 64 6f 77 6e 66 69 6c 65 00 } //1 搀睯普汩e
		$a_01_4 = {28 69 6e 66 6f 29 25 73 2d 3e 25 73 3a 25 73 } //1 (info)%s->%s:%s
		$a_01_5 = {72 61 6e 64 73 3d 25 73 26 61 63 63 3d 25 73 26 } //1 rands=%s&acc=%s&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}