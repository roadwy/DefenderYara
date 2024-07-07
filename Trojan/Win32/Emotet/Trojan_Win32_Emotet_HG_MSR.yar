
rule Trojan_Win32_Emotet_HG_MSR{
	meta:
		description = "Trojan:Win32/Emotet.HG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 4a 47 74 4b 6d 6d 62 58 42 72 67 7a 78 43 } //2 CJGtKmmbXBrgzxC
		$a_01_1 = {42 49 4e 44 53 43 52 42 2e 65 78 65 } //1 BINDSCRB.exe
		$a_01_2 = {56 70 63 56 78 4f 41 64 43 76 76 4e 4e 75 71 } //2 VpcVxOAdCvvNNuq
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}