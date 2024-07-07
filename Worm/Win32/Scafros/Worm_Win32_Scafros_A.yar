
rule Worm_Win32_Scafros_A{
	meta:
		description = "Worm:Win32/Scafros.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 7a 61 64 75 6e 69 6d 73 68 2f 69 70 2e 74 78 74 } //1 azadunimsh/ip.txt
		$a_01_1 = {23 73 74 61 72 74 6b 65 79 6c 6f 67 } //1 #startkeylog
		$a_01_2 = {23 62 6c 61 63 6b 63 68 61 74 } //1 #blackchat
		$a_01_3 = {23 70 68 6f 74 6f 73 65 6e 64 } //1 #photosend
		$a_01_4 = {23 79 61 68 6f 6f 75 73 72 70 77 64 } //1 #yahoousrpwd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}