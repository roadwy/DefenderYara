
rule HackTool_Win32_Meterpreter_E{
	meta:
		description = "HackTool:Win32/Meterpreter.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 2e 68 2e 65 2e 6c 2e 6c 2e 63 2e 6f 2e 64 2e 65 20 4f 6e 20 74 68 65 20 66 6c 79 20 2d 20 76 65 72 73 69 6f 6e 20 4f 56 48 } //01 00  S.h.e.l.l.c.o.d.e On the fly - version OVH
		$a_01_1 = {23 24 66 63 23 24 65 38 23 24 38 32 23 24 30 30 23 24 30 30 23 24 30 30 23 24 36 30 23 24 38 39 23 24 65 35 23 24 33 31 23 24 63 30 23 24 36 34 23 24 38 62 23 24 35 30 23 24 33 30 } //01 00  #$fc#$e8#$82#$00#$00#$00#$60#$89#$e5#$31#$c0#$64#$8b#$50#$30
		$a_01_2 = {6d 65 74 65 72 70 72 65 74 65 72 5f 72 65 76 65 72 73 65 5f } //00 00  meterpreter_reverse_
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}