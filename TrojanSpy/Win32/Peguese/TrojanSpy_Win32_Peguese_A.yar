
rule TrojanSpy_Win32_Peguese_A{
	meta:
		description = "TrojanSpy:Win32/Peguese.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 83 b4 03 00 00 90 09 19 00 83 bb 90 01 01 03 00 00 02 75 90 01 01 8d 55 f8 b8 90 01 03 00 e8 90 01 03 ff 8b 55 f8 90 00 } //1
		$a_01_1 = {70 72 6f 6a 65 63 74 31 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //1 牰橯捥ㅴ挮汰䌀汐灁汰瑥
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}