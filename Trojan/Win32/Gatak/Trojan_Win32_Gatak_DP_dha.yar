
rule Trojan_Win32_Gatak_DP_dha{
	meta:
		description = "Trojan:Win32/Gatak.DP!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 87 ea 00 10 e9 91 04 00 00 } //1
		$a_01_1 = {73 12 8b 45 08 03 45 f8 8b 4d 0c 03 4d f8 8a 09 88 08 eb df c6 45 ff 01 8a 45 ff c9 c3 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}