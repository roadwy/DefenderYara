
rule Trojan_Win32_Finkmilt_gen_B{
	meta:
		description = "Trojan:Win32/Finkmilt.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 4d 08 ff 75 08 e8 ?? ff ff ff } //3
		$a_01_1 = {6c 64 72 2e 64 6c 6c 2c 70 72 6b 74 } //1 ldr.dll,prkt
		$a_00_2 = {6e 6f 70 6f 72 2e 73 79 73 } //1 nopor.sys
		$a_00_3 = {64 6f 70 6f 70 2e 73 79 73 } //1 dopop.sys
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}