
rule TrojanSpy_Win32_Banzornk_A{
	meta:
		description = "TrojanSpy:Win32/Banzornk.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 75 6c 65 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //4 潍畤敬挮汰䌀汐灁汰瑥
		$a_03_1 = {56 50 53 e8 01 00 00 00 cc 58 89 c3 40 2d 00 ?? ?? 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc 75 19 c6 03 00 bb 00 10 00 00 } //2
		$a_01_2 = {8b 4d 0c c1 e9 02 8b 45 10 8b 5d 14 85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb f2 5e } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}