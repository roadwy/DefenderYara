
rule Trojan_Win32_Deminnix_gen_B{
	meta:
		description = "Trojan:Win32/Deminnix.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 64 24 6c 6a 2e 89 6e 18 89 5e 14 68 ?? ?? ?? ?? 66 89 5e 04 e8 ?? ?? ?? ?? c7 84 24 b4 00 00 00 ff ff ff ff } //1
		$a_01_1 = {2d 00 75 00 20 00 25 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 25 00 20 00 2d 00 70 00 20 00 25 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 25 00 } //1 -u %USERNAME% -p %PASSWORD%
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}