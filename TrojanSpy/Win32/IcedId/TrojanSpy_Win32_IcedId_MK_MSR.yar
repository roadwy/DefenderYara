
rule TrojanSpy_Win32_IcedId_MK_MSR{
	meta:
		description = "TrojanSpy:Win32/IcedId.MK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 85 b0 e5 ff ff ff 4d 10 40 33 d2 8b f1 f7 f6 8d b4 15 90 01 04 8a 1e 89 95 90 01 04 33 d2 0f b6 c3 03 c7 8b f9 f7 f7 8b fa 8d 84 3d 90 01 04 8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 90 01 04 8a 94 15 90 01 04 30 10 40 83 7d 10 00 89 85 90 01 04 75 9e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}