
rule Trojan_Win32_VB_AFX{
	meta:
		description = "Trojan:Win32/VB.AFX,SIGNATURE_TYPE_PEHSTR,20 00 20 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 44 50 46 6c 6f 6f 64 } //10 UDPFlood
		$a_01_1 = {53 65 72 69 4e 6f 41 6c } //10 SeriNoAl
		$a_01_2 = {68 00 61 00 72 00 79 00 76 00 69 00 64 00 65 00 6f 00 2e 00 65 00 78 00 65 00 } //10 haryvideo.exe
		$a_01_3 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 65 00 72 00 79 00 5c 00 65 00 72 00 79 00 2e 00 76 00 62 00 70 00 } //1 Desktop\ery\ery.vbp
		$a_01_4 = {54 00 72 00 65 00 6e 00 64 00 20 00 4d 00 69 00 63 00 72 00 6f 00 20 00 49 00 6e 00 63 00 } //1 Trend Micro Inc
		$a_01_5 = {48 00 69 00 6a 00 61 00 63 00 6b 00 20 00 54 00 68 00 69 00 73 00 } //1 Hijack This
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=32
 
}