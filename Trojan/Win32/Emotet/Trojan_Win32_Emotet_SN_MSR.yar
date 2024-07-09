
rule Trojan_Win32_Emotet_SN_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 73 67 6a 68 67 68 6a 66 64 46 41 44 5a 78 63 52 46 54 } //2 fsgjhghjfdFADZxcRFT
		$a_01_1 = {63 7a 73 73 64 6b 67 6e 62 6e 47 44 46 66 72 74 79 61 58 6c } //2 czssdkgnbnGDFfrtyaXl
		$a_02_2 = {50 72 6f 6a 65 63 74 [0-02] 2e 65 78 65 } //1
		$a_01_3 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 } //1 SetFileSecurity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}