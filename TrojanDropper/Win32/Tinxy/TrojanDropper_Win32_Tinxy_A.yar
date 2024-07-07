
rule TrojanDropper_Win32_Tinxy_A{
	meta:
		description = "TrojanDropper:Win32/Tinxy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a fc 50 ff 15 90 01 0c 6a 04 90 00 } //1
		$a_01_1 = {53 25 73 74 25 73 65 25 73 63 72 25 73 66 25 73 57 69 25 73 77 73 5c 25 73 72 72 25 73 56 65 25 73 6f 6e 25 73 70 25 73 72 65 25 73 68 25 73 6c 25 73 6c 64 25 73 73 } //1 S%st%se%scr%sf%sWi%sws\%srr%sVe%son%sp%sre%sh%sl%sld%ss
		$a_01_2 = {25 73 73 65 72 25 73 70 25 73 66 25 73 6e 65 25 73 72 6b 2e 25 73 6f 78 25 73 79 70 65 25 73 31 29 3b } //1 %sser%sp%sf%sne%srk.%sox%sype%s1);
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}