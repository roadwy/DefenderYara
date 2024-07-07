
rule Trojan_Win32_Emotet_RX_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RX!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 1f c1 f8 1f 8b ce c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 25 96 30 07 77 33 c1 } //1
		$a_01_1 = {81 e1 c8 20 6e 3b 33 c1 } //1
		$a_01_2 = {81 e1 32 88 db 0e 33 c1 } //1
		$a_01_3 = {81 e1 20 83 b8 ed 33 c1 81 e6 2c 61 0e ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}