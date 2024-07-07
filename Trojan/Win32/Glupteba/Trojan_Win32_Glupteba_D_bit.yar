
rule Trojan_Win32_Glupteba_D_bit{
	meta:
		description = "Trojan:Win32/Glupteba.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 74 65 72 6e 61 6c 62 6c 75 65 } //1 Eternalblue
		$a_01_1 = {61 74 74 61 63 6b 46 75 6e 63 } //1 attackFunc
		$a_01_2 = {63 6c 6f 75 64 6e 65 74 2e 65 78 65 } //1 cloudnet.exe
		$a_01_3 = {6e 61 64 65 71 75 61 6c 69 66 2e 63 6c 75 62 } //1 nadequalif.club
		$a_01_4 = {6f 6b 6f 6e 65 77 61 63 6f 6e 2e 63 6f 6d } //1 okonewacon.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}