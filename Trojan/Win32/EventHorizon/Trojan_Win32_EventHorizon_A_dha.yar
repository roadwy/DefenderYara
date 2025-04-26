
rule Trojan_Win32_EventHorizon_A_dha{
	meta:
		description = "Trojan:Win32/EventHorizon.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c7 45 b8 2d 65 6d 62 c7 45 bc 65 64 64 69 c7 45 c0 6e 67 4f 62 c7 45 c4 6a 65 63 74 } //1
		$a_02_1 = {4c 8b 40 08 48 8d 15 ?? fa 0c 00 48 8d 4d d8 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}