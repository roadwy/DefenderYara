
rule Backdoor_Win32_Refpron_M{
	meta:
		description = "Backdoor:Win32/Refpron.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 5f 72 5f 72 5f 6f 5f 72 5f 00 } //01 00 
		$a_01_1 = {63 6f 6d 73 61 33 32 2e 73 79 73 00 } //01 00  潣獭㍡⸲祳s
		$a_01_2 = {66 69 c0 6d ce 66 05 bf 58 } //01 00 
		$a_01_3 = {69 45 e8 6d ce 00 00 89 45 e4 ff 45 ec 66 8b 45 e4 66 05 bf 58 } //01 00 
		$a_01_4 = {62 66 6b 71 2e 63 6f 6d } //00 00  bfkq.com
	condition:
		any of ($a_*)
 
}