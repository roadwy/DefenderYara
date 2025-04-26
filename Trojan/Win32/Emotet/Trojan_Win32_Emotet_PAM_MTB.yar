
rule Trojan_Win32_Emotet_PAM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 ff 32 c9 33 f6 fe c7 8d [0-05] 0f b6 c7 03 d0 8a 1a 02 cb 0f b6 c1 88 [0-05] 8d [0-05] 03 c8 0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8a [0-05] 0f b6 84 05 [0-05] 30 04 3e 46 81 fe [0-05] 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}