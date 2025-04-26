
rule Trojan_Win32_Waprox_A{
	meta:
		description = "Trojan:Win32/Waprox.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 02 6b c0 1f 8b 4d 0c 03 4d fc 0f b6 11 03 c2 8b 4d 08 89 01 eb d5 } //2
		$a_01_1 = {70 6f 6c 79 5f 73 6f 63 6b 73 2e 64 6c 6c 00 77 6d 61 69 6e 00 } //1
		$a_01_2 = {70 72 6f 78 79 77 68 61 74 78 2e 63 6f 6d 00 } //1
		$a_01_3 = {4d 61 63 68 69 6e 65 47 75 69 64 00 62 6c 6f 77 6a 6f 62 00 } //1 慍档湩䝥極d汢睯潪b
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}