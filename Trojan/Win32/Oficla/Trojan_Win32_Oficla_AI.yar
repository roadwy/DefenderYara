
rule Trojan_Win32_Oficla_AI{
	meta:
		description = "Trojan:Win32/Oficla.AI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {64 62 67 68 65 6c 70 2e 64 6c 6c 00 [0-04] 73 62 69 65 64 6c 6c 2e 64 6c 6c 00 } //2
		$a_01_1 = {69 6d 67 2e 70 68 70 3f 76 3d 31 26 69 64 3d } //2 img.php?v=1&id=
		$a_03_2 = {7a 65 6e 74 6f 77 6f 72 6c 64 5f 90 10 0a 00 5f 64 61 64 61 00 } //2
		$a_01_3 = {6f 6e 6c 69 6e 65 2e 77 65 73 74 70 61 63 2e 63 6f 6d 2e 61 75 00 } //1 湯楬敮眮獥灴捡挮浯愮u
		$a_01_4 = {66 69 6e 61 6e 7a 70 6f 72 74 61 6c 2e 66 69 64 75 63 69 61 2e 64 65 00 } //1 楦慮穮潰瑲污昮摩捵慩搮e
		$a_01_5 = {69 62 61 6e 6b 2e 61 6c 66 61 62 61 6e 6b 2e 72 75 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}