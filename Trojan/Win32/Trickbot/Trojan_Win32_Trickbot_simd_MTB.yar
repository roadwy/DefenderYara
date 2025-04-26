
rule Trojan_Win32_Trickbot_simd_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.simd!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0f 4e 33 c1 4e 88 07 4e 85 d2 75 06 8b 55 14 8b 75 10 59 47 e2 e6 } //10
		$a_01_1 = {62 69 6a 61 77 65 65 64 2e 65 78 65 } //1 bijaweed.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}