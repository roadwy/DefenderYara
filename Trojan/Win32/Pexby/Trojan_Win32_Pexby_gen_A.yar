
rule Trojan_Win32_Pexby_gen_A{
	meta:
		description = "Trojan:Win32/Pexby.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c9 c1 c0 07 33 c1 42 42 0f b7 0a 66 85 c9 75 } //5
		$a_03_1 = {66 83 7e 02 2d 75 ?? 8b 4d 08 83 c6 04 83 c0 fe 89 31 89 07 43 [0-01] 3b 5d fc 7c } //5
		$a_03_2 = {0f b7 01 8b f0 81 e6 00 f0 00 00 bb 00 30 00 00 66 3b f3 75 ?? 8b ?? ?? 25 ff 0f 00 00 03 c2 01 30 } //5
		$a_01_3 = {6a 00 71 00 75 00 65 00 72 00 79 00 2d 00 6d 00 69 00 6e 00 2e 00 6a 00 73 00 2e 00 70 00 68 00 70 00 3f 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 jquery-min.js.php?username
		$a_01_4 = {6c 6f 63 6b 65 72 2e 64 6c 6c 00 46 31 00 46 32 00 46 33 00 46 34 00 49 6e 69 74 69 61 6c 69 7a 65 41 50 49 } //1 潬正牥搮汬䘀1㉆䘀3㑆䤀楮楴污穩䅥䥐
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}