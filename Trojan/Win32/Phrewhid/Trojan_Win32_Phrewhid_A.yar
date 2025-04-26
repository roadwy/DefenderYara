
rule Trojan_Win32_Phrewhid_A{
	meta:
		description = "Trojan:Win32/Phrewhid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d2 33 55 f4 88 17 46 47 8b 55 fc 85 d2 74 05 83 ea 04 8b 12 } //1
		$a_01_1 = {c1 e1 09 0f b7 58 f2 c1 eb 07 66 33 cb 66 89 48 0e eb 3f } //1
		$a_01_2 = {72 65 77 2e 70 68 70 3f 68 77 69 64 3d } //1 rew.php?hwid=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}