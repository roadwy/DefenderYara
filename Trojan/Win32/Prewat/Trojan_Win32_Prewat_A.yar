
rule Trojan_Win32_Prewat_A{
	meta:
		description = "Trojan:Win32/Prewat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 77 61 72 64 2e 52 65 77 61 72 64 50 6f 74 2e 63 6f 2e 6b 72 } //1 reward.RewardPot.co.kr
		$a_01_1 = {76 65 72 73 69 6f 6e 3d 25 73 26 63 6f 64 65 3d 25 73 26 6d 61 63 3d 25 73 26 6f 6c 64 76 65 72 73 69 6f 6e 3d 25 73 } //1 version=%s&code=%s&mac=%s&oldversion=%s
		$a_01_2 = {66 69 6c 65 30 3d 52 65 77 61 72 64 50 6f 74 2e } //1 file0=RewardPot.
		$a_01_3 = {5b 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 5d } //1 [TerminateProcess]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}