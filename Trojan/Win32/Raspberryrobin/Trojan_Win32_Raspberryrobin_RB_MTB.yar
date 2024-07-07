
rule Trojan_Win32_Raspberryrobin_RB_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 78 64 74 63 79 4f 69 6e 75 62 } //1 RxdtcyOinub
		$a_01_1 = {53 72 65 72 72 74 74 72 74 48 75 6e 69 6d } //1 SrerrttrtHunim
		$a_01_2 = {4f 69 6e 75 66 47 63 72 74 76 79 62 } //1 OinufGcrtvyb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}