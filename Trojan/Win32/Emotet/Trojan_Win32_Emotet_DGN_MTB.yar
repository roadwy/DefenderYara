
rule Trojan_Win32_Emotet_DGN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b f2 33 d2 8a 8c 34 ?? ?? ?? ?? 8b c1 88 8c 24 ?? ?? ?? ?? 25 ff 00 00 00 03 c7 bf ?? ?? ?? ?? f7 f7 8b fa 8a 94 3c 90 1b 00 88 94 34 } //1
		$a_81_1 = {4d 78 4e 4f 23 43 36 65 74 23 7b 45 48 47 35 61 34 4f 6a 25 7a 6b 66 40 32 6d 55 40 43 57 57 45 } //1 MxNO#C6et#{EHG5a4Oj%zkf@2mU@CWWE
		$a_81_2 = {4e 39 62 6b 56 7c 6c 4a 3f 35 7a 4e 5a 52 65 34 61 50 62 68 7d 47 7d 74 71 3f 67 34 52 65 40 6e 74 56 } //1 N9bkV|lJ?5zNZRe4aPbh}G}tq?g4Re@ntV
		$a_81_3 = {63 45 30 57 66 57 6c 79 } //1 cE0WfWly
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}