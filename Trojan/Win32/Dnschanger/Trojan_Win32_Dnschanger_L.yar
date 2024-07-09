
rule Trojan_Win32_Dnschanger_L{
	meta:
		description = "Trojan:Win32/Dnschanger.L,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {7c 24 1c b9 03 00 00 00 be ?? ?? 40 00 33 ?? f3 a6 } //3
		$a_01_1 = {8b c8 b8 f1 f0 f0 f0 81 f1 e9 e3 2e 01 } //3
		$a_01_2 = {c1 ea 04 83 c2 02 b8 c1 c0 c0 c0 f7 e2 } //3
		$a_01_3 = {44 4e 53 53 65 72 76 69 63 65 } //1 DNSService
		$a_01_4 = {69 6e 69 2d 69 6e 20 68 65 72 65 } //1 ini-in here
		$a_01_5 = {4e 45 54 20 53 54 4f 50 20 22 25 53 22 } //1 NET STOP "%S"
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}