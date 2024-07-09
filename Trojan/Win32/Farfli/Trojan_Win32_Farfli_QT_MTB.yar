
rule Trojan_Win32_Farfli_QT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.QT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {46 80 c2 4f 30 14 39 f7 e1 c1 ea ?? 8d 14 92 8b c1 2b c2 75 02 33 f6 41 3b 4d 0c 7c cf } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}