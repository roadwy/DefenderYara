
rule Trojan_Win32_Mewpet_gen_A{
	meta:
		description = "Trojan:Win32/Mewpet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 18 ff 53 34 a1 ?? ?? ?? ?? 8b 00 8b 10 ff 52 3c 33 c0 5a 59 59 } //2
		$a_03_1 = {70 74 6d 70 32 (64|68) 5f 73 76 63 } //1
		$a_01_2 = {3f 00 63 00 70 00 75 00 3d 00 25 00 35 00 2e 00 32 00 66 00 26 00 6d 00 65 00 6d 00 3d 00 25 00 35 00 2e 00 32 00 66 00 26 00 70 00 3d 00 25 00 64 00 } //1 ?cpu=%5.2f&mem=%5.2f&p=%d
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}