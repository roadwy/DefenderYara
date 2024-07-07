
rule TrojanDropper_Win32_VBInject_gen_A{
	meta:
		description = "TrojanDropper:Win32/VBInject.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 09 00 00 00 2b 48 90 01 01 c1 e1 04 8b 85 90 01 04 8b 40 90 01 01 03 c8 ff 15 90 01 04 8d 8d 90 01 04 51 8b 15 90 01 04 52 a1 90 01 04 50 e8 90 01 04 8d 8d 90 01 04 51 6a 00 ff 15 90 01 04 c7 45 90 01 01 0b 00 00 00 68 90 01 04 6a 00 ff 15 90 01 04 dd 9d 90 01 04 c7 45 90 01 01 0c 00 00 00 6a 00 6a 01 6a 01 6a 00 8d 95 90 01 04 52 6a 10 68 80 08 00 00 ff 15 90 00 } //2
		$a_03_1 = {c1 e0 04 8b 8d 90 01 04 8b 49 90 01 01 03 c8 ff 15 90 01 04 8d 95 90 01 04 52 a1 90 01 04 50 8b 0d 90 01 04 51 e8 90 01 04 8d 95 90 01 04 52 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}