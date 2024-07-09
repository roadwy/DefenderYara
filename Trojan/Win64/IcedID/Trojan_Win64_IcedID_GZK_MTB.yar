
rule Trojan_Win64_IcedID_GZK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {49 8b c6 4d 8d 40 ?? 48 f7 e1 41 ff c1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 49 63 c9 48 81 f9 ?? ?? ?? ?? 72 d3 } //10
		$a_01_1 = {6f 6b 6c 77 70 62 72 77 6f 79 69 73 62 } //1 oklwpbrwoyisb
		$a_01_2 = {71 66 72 66 71 61 7a 64 76 74 } //1 qfrfqazdvt
		$a_01_3 = {6e 78 79 61 6c 6f 69 64 67 72 } //1 nxyaloidgr
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}