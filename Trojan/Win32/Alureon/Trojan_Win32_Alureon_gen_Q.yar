
rule Trojan_Win32_Alureon_gen_Q{
	meta:
		description = "Trojan:Win32/Alureon.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a d0 80 c2 54 30 90 90 ?? ?? ?? ?? 40 3b c1 72 f0 } //1
		$a_03_1 = {6a 1a 50 c7 45 f4 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85 aa 00 00 00 } //1
		$a_01_2 = {69 61 6d 66 61 6d 6f 75 73 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}