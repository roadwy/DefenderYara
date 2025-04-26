
rule Trojan_Win32_Molgomsg_B{
	meta:
		description = "Trojan:Win32/Molgomsg.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e0 5b cf 3c ?? c7 45 e4 ?? ?? ?? ?? e8 } //1
		$a_01_1 = {69 d2 51 2d 9e cc c1 c2 0f 69 d2 93 35 87 1b 33 c2 } //1
		$a_01_2 = {00 77 69 6e 73 79 73 33 32 00 } //1 眀湩祳㍳2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}