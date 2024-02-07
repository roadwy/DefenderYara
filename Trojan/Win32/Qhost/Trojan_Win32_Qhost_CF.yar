
rule Trojan_Win32_Qhost_CF{
	meta:
		description = "Trojan:Win32/Qhost.CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 00 } //01 00  牤癩牥⽳瑥⽣潨瑳s
		$a_01_1 = {31 37 33 2e 32 31 32 2e 32 30 37 2e 32 31 36 20 20 20 20 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 00 } //01 00  㜱⸳ㄲ⸲〲⸷ㄲ‶†瘠潫瑮歡整爮u
		$a_01_2 = {64 65 6c 65 74 65 2e 62 61 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}