
rule Trojan_Win32_Ninunarch_M{
	meta:
		description = "Trojan:Win32/Ninunarch.M,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 73 68 4d 61 67 6e 61 74 5c 64 61 74 61 00 49 4e 46 4f } //01 00  慃桳慍湧瑡摜瑡a义但
		$a_01_1 = {69 63 6f 2e 64 61 74 00 69 63 6f 2e 69 63 6f 00 46 4c 49 53 54 00 43 4f 56 45 52 } //01 00 
		$a_01_2 = {6b 65 72 6e 65 6c 33 32 3a 3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 } //00 00  kernel32::CreateMutexA(i 0, i 0, t "
	condition:
		any of ($a_*)
 
}