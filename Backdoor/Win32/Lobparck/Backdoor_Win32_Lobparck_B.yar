
rule Backdoor_Win32_Lobparck_B{
	meta:
		description = "Backdoor:Win32/Lobparck.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 70 6b 2e 64 6c 6c } //1 lpk.dll
		$a_01_1 = {6d 79 57 6f 72 6b 53 74 61 72 74 00 64 6f 75 62 6c 65 73 61 66 65 } //1 祭潗歲瑓牡t潤扵敬慳敦
		$a_01_2 = {43 44 41 20 6d 67 72 } //1 CDA mgr
		$a_00_3 = {33 c9 33 c0 89 0d 48 53 40 00 a2 04 52 40 00 89 0d 4c 53 40 00 a2 dc 50 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}