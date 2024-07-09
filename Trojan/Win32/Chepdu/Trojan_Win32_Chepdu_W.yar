
rule Trojan_Win32_Chepdu_W{
	meta:
		description = "Trojan:Win32/Chepdu.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 6d 8b 04 [0-05] 68 80 01 00 00 50 6a 00 e8 ?? ?? 00 00 } //1
		$a_00_1 = {be 80 d1 f0 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}