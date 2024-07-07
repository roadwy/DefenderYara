
rule Trojan_Win32_Tacorti_A{
	meta:
		description = "Trojan:Win32/Tacorti.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 c3 01 74 22 8d 45 ec 8b 55 fc 0f b6 54 1a ff 03 55 f8 03 55 f4 } //1
		$a_01_1 = {50 8b 07 8b 40 14 03 45 f0 50 8b 07 8b 40 0c 03 45 ec 50 53 ff 15 4c 18 41 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}